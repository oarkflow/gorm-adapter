// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gormadapter

import (
	"fmt"
	"strings"

	"github.com/oarkflow/fastac/api"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	defaultTableName = "casbin_rule"
)

type customTableKey struct{}

type CasbinRule struct {
	ID    uint   `gorm:"primaryKey;autoIncrement"`
	Ptype string `gorm:"size:100"`
	V0    string `gorm:"size:100"`
	V1    string `gorm:"size:100"`
	V2    string `gorm:"size:100"`
	V3    string `gorm:"size:100"`
	V4    string `gorm:"size:100"`
	V5    string `gorm:"size:100"`
	V6    string `gorm:"size:25"`
	V7    string `gorm:"size:25"`
}

func (CasbinRule) TableName() string {
	return "casbin_rule"
}

type Filter struct {
	Ptype []string
	V0    []string
	V1    []string
	V2    []string
	V3    []string
	V4    []string
	V5    []string
	V6    []string
	V7    []string
}

// Adapter represents the Gorm adapter for policy storage.
type Adapter struct {
	tableName  string
	db         *gorm.DB
	isFiltered bool
}

// finalizer is the destructor for Adapter.
func finalizer(a *Adapter) {
	sqlDB, err := a.db.DB()
	if err != nil {
		panic(err)
	}
	err = sqlDB.Close()
	if err != nil {
		panic(err)
	}
}

// NewAdapterByDBUseTableName creates gorm-adapter by an existing Gorm instance and the specified table prefix and table name
// Example: gormadapter.NewAdapterByDBUseTableName(&db, "cms", "casbin") Automatically generate table name like this "cms_casbin"
func NewAdapterWithTable(db *gorm.DB, tableName string) (*Adapter, error) {
	if len(tableName) == 0 {
		tableName = defaultTableName
	}

	a := &Adapter{
		tableName: tableName,
	}

	a.db = db.Scopes(a.casbinRuleTable()).Session(&gorm.Session{Context: db.Statement.Context})
	err := a.createTable()
	if err != nil {
		return nil, err
	}

	return a, nil
}

// NewAdapterWithDB creates gorm-adapter by an existing Gorm instance
func NewAdapter(db *gorm.DB) (*Adapter, error) {
	return NewAdapterWithTable(db, defaultTableName)
}

// AddLogger adds logger to db
func (a *Adapter) AddLogger(l logger.Interface) {
	a.db = a.db.Session(&gorm.Session{Logger: l, Context: a.db.Statement.Context})
}

func (a *Adapter) Close() error {
	finalizer(a)
	return nil
}

// getTableInstance return the dynamic table name
func (a *Adapter) getTableInstance() *CasbinRule {
	return &CasbinRule{}
}

func (a *Adapter) getFullTableName() string {
	return a.tableName
}

func (a *Adapter) casbinRuleTable() func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		tableName := a.getFullTableName()
		return db.Table(tableName)
	}
}

func (a *Adapter) createTable() error {
	t := a.db.Statement.Context.Value(customTableKey{})

	if t != nil {
		return a.db.AutoMigrate(t)
	}

	t = a.getTableInstance()
	if err := a.db.AutoMigrate(t); err != nil {
		return err
	}

	tableName := a.getFullTableName()
	index := strings.ReplaceAll("idx_"+tableName, ".", "_")
	hasIndex := a.db.Migrator().HasIndex(t, index)
	if !hasIndex {
		if err := a.db.Exec(fmt.Sprintf("CREATE UNIQUE INDEX %s ON %s (ptype,v0,v1,v2,v3,v4,v5,v6,v7)", index, tableName)).Error; err != nil {
			return err
		}
	}
	return nil
}

func (a *Adapter) dropTable() error {
	t := a.db.Statement.Context.Value(customTableKey{})
	if t == nil {
		return a.db.Migrator().DropTable(a.getTableInstance())
	}

	return a.db.Migrator().DropTable(t)
}

func loadPolicyLine(line CasbinRule, model api.IAddRuleBool) {
	var p = []string{line.Ptype,
		line.V0, line.V1, line.V2,
		line.V3, line.V4, line.V5,
		line.V6, line.V7}

	index := len(p) - 1
	for p[index] == "" {
		index--
	}
	index += 1
	p = p[:index]

	model.AddRule(p)
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(model api.IAddRuleBool) error {
	var lines []CasbinRule
	if err := a.db.Order("ID").Find(&lines).Error; err != nil {
		return err
	}

	for _, line := range lines {
		loadPolicyLine(line, model)
	}

	return nil
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *Adapter) IsFiltered() bool {
	return a.isFiltered
}

func (a *Adapter) savePolicyLine(ptype string, rule []string) CasbinRule {
	line := a.getTableInstance()

	line.Ptype = ptype
	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}
	if len(rule) > 6 {
		line.V6 = rule[6]
	}
	if len(rule) > 7 {
		line.V7 = rule[7]
	}

	return *line
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model api.IRangeRules) error {
	err := a.dropTable()
	if err != nil {
		return err
	}
	err = a.createTable()
	if err != nil {
		return err
	}

	var createErr error
	var lines []CasbinRule
	flushEvery := 1000
	model.RangeRules(func(rule []string) bool {
		lines = append(lines, a.savePolicyLine(rule[0], rule[1:]))
		if len(lines) > flushEvery {
			if createErr := a.db.Create(&lines).Error; createErr != nil {
				return false
			}
			lines = nil
		}
		return true
	})
	if createErr != nil {
		return createErr
	}

	if err := a.db.Create(&lines).Error; err != nil {
		return err
	}

	return nil
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddRule(rule []string) error {
	line := a.savePolicyLine(rule[0], rule[1:])
	err := a.db.Create(&line).Error
	return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemoveRule(rule []string) error {
	line := a.savePolicyLine(rule[0], rule[1:])
	err := a.rawDelete(a.db, line) // can't use db.Delete as we're not using primary key http://jinzhu.me/gorm/crud.html#delete
	return err
}

// AddPolicies adds multiple policy rules to the storage.
func (a *Adapter) AddRules(rules [][]string) error {
	var lines []CasbinRule
	for _, rule := range rules {
		line := a.savePolicyLine(rule[0], rule[1:])
		lines = append(lines, line)
	}
	return a.db.Create(&lines).Error
}

// RemovePolicies removes multiple policy rules from the storage.
func (a *Adapter) RemoveRules(rules [][]string) error {
	return a.db.Transaction(func(tx *gorm.DB) error {
		for _, rule := range rules {
			line := a.savePolicyLine(rule[0], rule[1:])
			if err := a.rawDelete(tx, line); err != nil { // can't use db.Delete as we're not using primary key http://jinzhu.me/gorm/crud.html#delete
				return err
			}
		}
		return nil
	})
}

func (a *Adapter) rawDelete(db *gorm.DB, line CasbinRule) error {
	queryArgs := []interface{}{line.Ptype}

	queryStr := "ptype = ?"
	if line.V0 != "" {
		queryStr += " and v0 = ?"
		queryArgs = append(queryArgs, line.V0)
	}
	if line.V1 != "" {
		queryStr += " and v1 = ?"
		queryArgs = append(queryArgs, line.V1)
	}
	if line.V2 != "" {
		queryStr += " and v2 = ?"
		queryArgs = append(queryArgs, line.V2)
	}
	if line.V3 != "" {
		queryStr += " and v3 = ?"
		queryArgs = append(queryArgs, line.V3)
	}
	if line.V4 != "" {
		queryStr += " and v4 = ?"
		queryArgs = append(queryArgs, line.V4)
	}
	if line.V5 != "" {
		queryStr += " and v5 = ?"
		queryArgs = append(queryArgs, line.V5)
	}
	if line.V6 != "" {
		queryStr += " and v6 = ?"
		queryArgs = append(queryArgs, line.V6)
	}
	if line.V7 != "" {
		queryStr += " and v7 = ?"
		queryArgs = append(queryArgs, line.V7)
	}
	args := append([]interface{}{queryStr}, queryArgs...)
	err := db.Delete(a.getTableInstance(), args...).Error
	return err
}

func (c *CasbinRule) toStringPolicy() []string {
	policy := make([]string, 0)
	if c.Ptype != "" {
		policy = append(policy, c.Ptype)
	}
	if c.V0 != "" {
		policy = append(policy, c.V0)
	}
	if c.V1 != "" {
		policy = append(policy, c.V1)
	}
	if c.V2 != "" {
		policy = append(policy, c.V2)
	}
	if c.V3 != "" {
		policy = append(policy, c.V3)
	}
	if c.V4 != "" {
		policy = append(policy, c.V4)
	}
	if c.V5 != "" {
		policy = append(policy, c.V5)
	}
	if c.V6 != "" {
		policy = append(policy, c.V6)
	}
	if c.V7 != "" {
		policy = append(policy, c.V7)
	}
	return policy
}
