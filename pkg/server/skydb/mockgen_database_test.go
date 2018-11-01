// Code generated by MockGen. DO NOT EDIT.
// Source: database.go

// Package skydb is a generated GoMock package.
package skydb

import (
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
)

// MockDatabase is a mock of Database interface
type MockDatabase struct {
	ctrl     *gomock.Controller
	recorder *MockDatabaseMockRecorder
}

// MockDatabaseMockRecorder is the mock recorder for MockDatabase
type MockDatabaseMockRecorder struct {
	mock *MockDatabase
}

// NewMockDatabase creates a new mock instance
func NewMockDatabase(ctrl *gomock.Controller) *MockDatabase {
	mock := &MockDatabase{ctrl: ctrl}
	mock.recorder = &MockDatabaseMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockDatabase) EXPECT() *MockDatabaseMockRecorder {
	return m.recorder
}

// Conn mocks base method
func (m *MockDatabase) Conn() Conn {
	ret := m.ctrl.Call(m, "Conn")
	ret0, _ := ret[0].(Conn)
	return ret0
}

// Conn indicates an expected call of Conn
func (mr *MockDatabaseMockRecorder) Conn() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Conn", reflect.TypeOf((*MockDatabase)(nil).Conn))
}

// ID mocks base method
func (m *MockDatabase) ID() string {
	ret := m.ctrl.Call(m, "ID")
	ret0, _ := ret[0].(string)
	return ret0
}

// ID indicates an expected call of ID
func (mr *MockDatabaseMockRecorder) ID() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ID", reflect.TypeOf((*MockDatabase)(nil).ID))
}

// DatabaseType mocks base method
func (m *MockDatabase) DatabaseType() DatabaseType {
	ret := m.ctrl.Call(m, "DatabaseType")
	ret0, _ := ret[0].(DatabaseType)
	return ret0
}

// DatabaseType indicates an expected call of DatabaseType
func (mr *MockDatabaseMockRecorder) DatabaseType() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DatabaseType", reflect.TypeOf((*MockDatabase)(nil).DatabaseType))
}

// UserRecordType mocks base method
func (m *MockDatabase) UserRecordType() string {
	ret := m.ctrl.Call(m, "UserRecordType")
	ret0, _ := ret[0].(string)
	return ret0
}

// UserRecordType indicates an expected call of UserRecordType
func (mr *MockDatabaseMockRecorder) UserRecordType() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UserRecordType", reflect.TypeOf((*MockDatabase)(nil).UserRecordType))
}

// TableName mocks base method
func (m *MockDatabase) TableName(table string) string {
	ret := m.ctrl.Call(m, "TableName", table)
	ret0, _ := ret[0].(string)
	return ret0
}

// TableName indicates an expected call of TableName
func (mr *MockDatabaseMockRecorder) TableName(table interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TableName", reflect.TypeOf((*MockDatabase)(nil).TableName), table)
}

// IsReadOnly mocks base method
func (m *MockDatabase) IsReadOnly() bool {
	ret := m.ctrl.Call(m, "IsReadOnly")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsReadOnly indicates an expected call of IsReadOnly
func (mr *MockDatabaseMockRecorder) IsReadOnly() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsReadOnly", reflect.TypeOf((*MockDatabase)(nil).IsReadOnly))
}

// RemoteColumnTypes mocks base method
func (m *MockDatabase) RemoteColumnTypes(recordType string) (RecordSchema, error) {
	ret := m.ctrl.Call(m, "RemoteColumnTypes", recordType)
	ret0, _ := ret[0].(RecordSchema)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RemoteColumnTypes indicates an expected call of RemoteColumnTypes
func (mr *MockDatabaseMockRecorder) RemoteColumnTypes(recordType interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoteColumnTypes", reflect.TypeOf((*MockDatabase)(nil).RemoteColumnTypes), recordType)
}

// Get mocks base method
func (m *MockDatabase) Get(id RecordID, record *Record) error {
	ret := m.ctrl.Call(m, "Get", id, record)
	ret0, _ := ret[0].(error)
	return ret0
}

// Get indicates an expected call of Get
func (mr *MockDatabaseMockRecorder) Get(id, record interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockDatabase)(nil).Get), id, record)
}

// GetByIDs mocks base method
func (m *MockDatabase) GetByIDs(ids []RecordID, accessControlOptions *AccessControlOptions) (*Rows, error) {
	ret := m.ctrl.Call(m, "GetByIDs", ids, accessControlOptions)
	ret0, _ := ret[0].(*Rows)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByIDs indicates an expected call of GetByIDs
func (mr *MockDatabaseMockRecorder) GetByIDs(ids, accessControlOptions interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByIDs", reflect.TypeOf((*MockDatabase)(nil).GetByIDs), ids, accessControlOptions)
}

// Save mocks base method
func (m *MockDatabase) Save(record *Record) error {
	ret := m.ctrl.Call(m, "Save", record)
	ret0, _ := ret[0].(error)
	return ret0
}

// Save indicates an expected call of Save
func (mr *MockDatabaseMockRecorder) Save(record interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Save", reflect.TypeOf((*MockDatabase)(nil).Save), record)
}

// Delete mocks base method
func (m *MockDatabase) Delete(id RecordID) error {
	ret := m.ctrl.Call(m, "Delete", id)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete
func (mr *MockDatabaseMockRecorder) Delete(id interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockDatabase)(nil).Delete), id)
}

// Query mocks base method
func (m *MockDatabase) Query(query *Query, accessControlOptions *AccessControlOptions) (*Rows, error) {
	ret := m.ctrl.Call(m, "Query", query, accessControlOptions)
	ret0, _ := ret[0].(*Rows)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Query indicates an expected call of Query
func (mr *MockDatabaseMockRecorder) Query(query, accessControlOptions interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Query", reflect.TypeOf((*MockDatabase)(nil).Query), query, accessControlOptions)
}

// QueryCount mocks base method
func (m *MockDatabase) QueryCount(query *Query, accessControlOptions *AccessControlOptions) (uint64, error) {
	ret := m.ctrl.Call(m, "QueryCount", query, accessControlOptions)
	ret0, _ := ret[0].(uint64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// QueryCount indicates an expected call of QueryCount
func (mr *MockDatabaseMockRecorder) QueryCount(query, accessControlOptions interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueryCount", reflect.TypeOf((*MockDatabase)(nil).QueryCount), query, accessControlOptions)
}

// Extend mocks base method
func (m *MockDatabase) Extend(recordType string, schema RecordSchema) (bool, error) {
	ret := m.ctrl.Call(m, "Extend", recordType, schema)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Extend indicates an expected call of Extend
func (mr *MockDatabaseMockRecorder) Extend(recordType, schema interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Extend", reflect.TypeOf((*MockDatabase)(nil).Extend), recordType, schema)
}

// RenameSchema mocks base method
func (m *MockDatabase) RenameSchema(recordType, oldColumnName, newColumnName string) error {
	ret := m.ctrl.Call(m, "RenameSchema", recordType, oldColumnName, newColumnName)
	ret0, _ := ret[0].(error)
	return ret0
}

// RenameSchema indicates an expected call of RenameSchema
func (mr *MockDatabaseMockRecorder) RenameSchema(recordType, oldColumnName, newColumnName interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RenameSchema", reflect.TypeOf((*MockDatabase)(nil).RenameSchema), recordType, oldColumnName, newColumnName)
}

// DeleteSchema mocks base method
func (m *MockDatabase) DeleteSchema(recordType, columnName string) error {
	ret := m.ctrl.Call(m, "DeleteSchema", recordType, columnName)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteSchema indicates an expected call of DeleteSchema
func (mr *MockDatabaseMockRecorder) DeleteSchema(recordType, columnName interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteSchema", reflect.TypeOf((*MockDatabase)(nil).DeleteSchema), recordType, columnName)
}

// GetSchema mocks base method
func (m *MockDatabase) GetSchema(recordType string) (RecordSchema, error) {
	ret := m.ctrl.Call(m, "GetSchema", recordType)
	ret0, _ := ret[0].(RecordSchema)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSchema indicates an expected call of GetSchema
func (mr *MockDatabaseMockRecorder) GetSchema(recordType interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSchema", reflect.TypeOf((*MockDatabase)(nil).GetSchema), recordType)
}

// GetRecordSchemas mocks base method
func (m *MockDatabase) GetRecordSchemas() (map[string]RecordSchema, error) {
	ret := m.ctrl.Call(m, "GetRecordSchemas")
	ret0, _ := ret[0].(map[string]RecordSchema)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRecordSchemas indicates an expected call of GetRecordSchemas
func (mr *MockDatabaseMockRecorder) GetRecordSchemas() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRecordSchemas", reflect.TypeOf((*MockDatabase)(nil).GetRecordSchemas))
}

// GetSubscription mocks base method
func (m *MockDatabase) GetSubscription(key, deviceID string, subscription *Subscription) error {
	ret := m.ctrl.Call(m, "GetSubscription", key, deviceID, subscription)
	ret0, _ := ret[0].(error)
	return ret0
}

// GetSubscription indicates an expected call of GetSubscription
func (mr *MockDatabaseMockRecorder) GetSubscription(key, deviceID, subscription interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSubscription", reflect.TypeOf((*MockDatabase)(nil).GetSubscription), key, deviceID, subscription)
}

// SaveSubscription mocks base method
func (m *MockDatabase) SaveSubscription(subscription *Subscription) error {
	ret := m.ctrl.Call(m, "SaveSubscription", subscription)
	ret0, _ := ret[0].(error)
	return ret0
}

// SaveSubscription indicates an expected call of SaveSubscription
func (mr *MockDatabaseMockRecorder) SaveSubscription(subscription interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveSubscription", reflect.TypeOf((*MockDatabase)(nil).SaveSubscription), subscription)
}

// DeleteSubscription mocks base method
func (m *MockDatabase) DeleteSubscription(key, deviceID string) error {
	ret := m.ctrl.Call(m, "DeleteSubscription", key, deviceID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteSubscription indicates an expected call of DeleteSubscription
func (mr *MockDatabaseMockRecorder) DeleteSubscription(key, deviceID interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteSubscription", reflect.TypeOf((*MockDatabase)(nil).DeleteSubscription), key, deviceID)
}

// GetSubscriptionsByDeviceID mocks base method
func (m *MockDatabase) GetSubscriptionsByDeviceID(deviceID string) []Subscription {
	ret := m.ctrl.Call(m, "GetSubscriptionsByDeviceID", deviceID)
	ret0, _ := ret[0].([]Subscription)
	return ret0
}

// GetSubscriptionsByDeviceID indicates an expected call of GetSubscriptionsByDeviceID
func (mr *MockDatabaseMockRecorder) GetSubscriptionsByDeviceID(deviceID interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSubscriptionsByDeviceID", reflect.TypeOf((*MockDatabase)(nil).GetSubscriptionsByDeviceID), deviceID)
}

// GetMatchingSubscriptions mocks base method
func (m *MockDatabase) GetMatchingSubscriptions(record *Record) []Subscription {
	ret := m.ctrl.Call(m, "GetMatchingSubscriptions", record)
	ret0, _ := ret[0].([]Subscription)
	return ret0
}

// GetMatchingSubscriptions indicates an expected call of GetMatchingSubscriptions
func (mr *MockDatabaseMockRecorder) GetMatchingSubscriptions(record interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMatchingSubscriptions", reflect.TypeOf((*MockDatabase)(nil).GetMatchingSubscriptions), record)
}

// GetIndexesByRecordType mocks base method
func (m *MockDatabase) GetIndexesByRecordType(recordType string) (map[string]Index, error) {
	ret := m.ctrl.Call(m, "GetIndexesByRecordType", recordType)
	ret0, _ := ret[0].(map[string]Index)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetIndexesByRecordType indicates an expected call of GetIndexesByRecordType
func (mr *MockDatabaseMockRecorder) GetIndexesByRecordType(recordType interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetIndexesByRecordType", reflect.TypeOf((*MockDatabase)(nil).GetIndexesByRecordType), recordType)
}

// SaveIndex mocks base method
func (m *MockDatabase) SaveIndex(recordType, indexName string, index Index) error {
	ret := m.ctrl.Call(m, "SaveIndex", recordType, indexName, index)
	ret0, _ := ret[0].(error)
	return ret0
}

// SaveIndex indicates an expected call of SaveIndex
func (mr *MockDatabaseMockRecorder) SaveIndex(recordType, indexName, index interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveIndex", reflect.TypeOf((*MockDatabase)(nil).SaveIndex), recordType, indexName, index)
}

// DeleteIndex mocks base method
func (m *MockDatabase) DeleteIndex(recordType, indexName string) error {
	ret := m.ctrl.Call(m, "DeleteIndex", recordType, indexName)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteIndex indicates an expected call of DeleteIndex
func (mr *MockDatabaseMockRecorder) DeleteIndex(recordType, indexName interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteIndex", reflect.TypeOf((*MockDatabase)(nil).DeleteIndex), recordType, indexName)
}

// MockTransactional is a mock of Transactional interface
type MockTransactional struct {
	ctrl     *gomock.Controller
	recorder *MockTransactionalMockRecorder
}

// MockTransactionalMockRecorder is the mock recorder for MockTransactional
type MockTransactionalMockRecorder struct {
	mock *MockTransactional
}

// NewMockTransactional creates a new mock instance
func NewMockTransactional(ctrl *gomock.Controller) *MockTransactional {
	mock := &MockTransactional{ctrl: ctrl}
	mock.recorder = &MockTransactionalMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockTransactional) EXPECT() *MockTransactionalMockRecorder {
	return m.recorder
}

// Begin mocks base method
func (m *MockTransactional) Begin() error {
	ret := m.ctrl.Call(m, "Begin")
	ret0, _ := ret[0].(error)
	return ret0
}

// Begin indicates an expected call of Begin
func (mr *MockTransactionalMockRecorder) Begin() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Begin", reflect.TypeOf((*MockTransactional)(nil).Begin))
}

// Commit mocks base method
func (m *MockTransactional) Commit() error {
	ret := m.ctrl.Call(m, "Commit")
	ret0, _ := ret[0].(error)
	return ret0
}

// Commit indicates an expected call of Commit
func (mr *MockTransactionalMockRecorder) Commit() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Commit", reflect.TypeOf((*MockTransactional)(nil).Commit))
}

// Rollback mocks base method
func (m *MockTransactional) Rollback() error {
	ret := m.ctrl.Call(m, "Rollback")
	ret0, _ := ret[0].(error)
	return ret0
}

// Rollback indicates an expected call of Rollback
func (mr *MockTransactionalMockRecorder) Rollback() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Rollback", reflect.TypeOf((*MockTransactional)(nil).Rollback))
}

// MockTxDatabase is a mock of TxDatabase interface
type MockTxDatabase struct {
	ctrl     *gomock.Controller
	recorder *MockTxDatabaseMockRecorder
}

// MockTxDatabaseMockRecorder is the mock recorder for MockTxDatabase
type MockTxDatabaseMockRecorder struct {
	mock *MockTxDatabase
}

// NewMockTxDatabase creates a new mock instance
func NewMockTxDatabase(ctrl *gomock.Controller) *MockTxDatabase {
	mock := &MockTxDatabase{ctrl: ctrl}
	mock.recorder = &MockTxDatabaseMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockTxDatabase) EXPECT() *MockTxDatabaseMockRecorder {
	return m.recorder
}

// Begin mocks base method
func (m *MockTxDatabase) Begin() error {
	ret := m.ctrl.Call(m, "Begin")
	ret0, _ := ret[0].(error)
	return ret0
}

// Begin indicates an expected call of Begin
func (mr *MockTxDatabaseMockRecorder) Begin() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Begin", reflect.TypeOf((*MockTxDatabase)(nil).Begin))
}

// Commit mocks base method
func (m *MockTxDatabase) Commit() error {
	ret := m.ctrl.Call(m, "Commit")
	ret0, _ := ret[0].(error)
	return ret0
}

// Commit indicates an expected call of Commit
func (mr *MockTxDatabaseMockRecorder) Commit() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Commit", reflect.TypeOf((*MockTxDatabase)(nil).Commit))
}

// Rollback mocks base method
func (m *MockTxDatabase) Rollback() error {
	ret := m.ctrl.Call(m, "Rollback")
	ret0, _ := ret[0].(error)
	return ret0
}

// Rollback indicates an expected call of Rollback
func (mr *MockTxDatabaseMockRecorder) Rollback() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Rollback", reflect.TypeOf((*MockTxDatabase)(nil).Rollback))
}

// Conn mocks base method
func (m *MockTxDatabase) Conn() Conn {
	ret := m.ctrl.Call(m, "Conn")
	ret0, _ := ret[0].(Conn)
	return ret0
}

// Conn indicates an expected call of Conn
func (mr *MockTxDatabaseMockRecorder) Conn() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Conn", reflect.TypeOf((*MockTxDatabase)(nil).Conn))
}

// ID mocks base method
func (m *MockTxDatabase) ID() string {
	ret := m.ctrl.Call(m, "ID")
	ret0, _ := ret[0].(string)
	return ret0
}

// ID indicates an expected call of ID
func (mr *MockTxDatabaseMockRecorder) ID() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ID", reflect.TypeOf((*MockTxDatabase)(nil).ID))
}

// DatabaseType mocks base method
func (m *MockTxDatabase) DatabaseType() DatabaseType {
	ret := m.ctrl.Call(m, "DatabaseType")
	ret0, _ := ret[0].(DatabaseType)
	return ret0
}

// DatabaseType indicates an expected call of DatabaseType
func (mr *MockTxDatabaseMockRecorder) DatabaseType() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DatabaseType", reflect.TypeOf((*MockTxDatabase)(nil).DatabaseType))
}

// UserRecordType mocks base method
func (m *MockTxDatabase) UserRecordType() string {
	ret := m.ctrl.Call(m, "UserRecordType")
	ret0, _ := ret[0].(string)
	return ret0
}

// UserRecordType indicates an expected call of UserRecordType
func (mr *MockTxDatabaseMockRecorder) UserRecordType() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UserRecordType", reflect.TypeOf((*MockTxDatabase)(nil).UserRecordType))
}

// TableName mocks base method
func (m *MockTxDatabase) TableName(table string) string {
	ret := m.ctrl.Call(m, "TableName", table)
	ret0, _ := ret[0].(string)
	return ret0
}

// TableName indicates an expected call of TableName
func (mr *MockTxDatabaseMockRecorder) TableName(table interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TableName", reflect.TypeOf((*MockTxDatabase)(nil).TableName), table)
}

// IsReadOnly mocks base method
func (m *MockTxDatabase) IsReadOnly() bool {
	ret := m.ctrl.Call(m, "IsReadOnly")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsReadOnly indicates an expected call of IsReadOnly
func (mr *MockTxDatabaseMockRecorder) IsReadOnly() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsReadOnly", reflect.TypeOf((*MockTxDatabase)(nil).IsReadOnly))
}

// RemoteColumnTypes mocks base method
func (m *MockTxDatabase) RemoteColumnTypes(recordType string) (RecordSchema, error) {
	ret := m.ctrl.Call(m, "RemoteColumnTypes", recordType)
	ret0, _ := ret[0].(RecordSchema)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RemoteColumnTypes indicates an expected call of RemoteColumnTypes
func (mr *MockTxDatabaseMockRecorder) RemoteColumnTypes(recordType interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RemoteColumnTypes", reflect.TypeOf((*MockTxDatabase)(nil).RemoteColumnTypes), recordType)
}

// Get mocks base method
func (m *MockTxDatabase) Get(id RecordID, record *Record) error {
	ret := m.ctrl.Call(m, "Get", id, record)
	ret0, _ := ret[0].(error)
	return ret0
}

// Get indicates an expected call of Get
func (mr *MockTxDatabaseMockRecorder) Get(id, record interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Get", reflect.TypeOf((*MockTxDatabase)(nil).Get), id, record)
}

// GetByIDs mocks base method
func (m *MockTxDatabase) GetByIDs(ids []RecordID, accessControlOptions *AccessControlOptions) (*Rows, error) {
	ret := m.ctrl.Call(m, "GetByIDs", ids, accessControlOptions)
	ret0, _ := ret[0].(*Rows)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByIDs indicates an expected call of GetByIDs
func (mr *MockTxDatabaseMockRecorder) GetByIDs(ids, accessControlOptions interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByIDs", reflect.TypeOf((*MockTxDatabase)(nil).GetByIDs), ids, accessControlOptions)
}

// Save mocks base method
func (m *MockTxDatabase) Save(record *Record) error {
	ret := m.ctrl.Call(m, "Save", record)
	ret0, _ := ret[0].(error)
	return ret0
}

// Save indicates an expected call of Save
func (mr *MockTxDatabaseMockRecorder) Save(record interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Save", reflect.TypeOf((*MockTxDatabase)(nil).Save), record)
}

// Delete mocks base method
func (m *MockTxDatabase) Delete(id RecordID) error {
	ret := m.ctrl.Call(m, "Delete", id)
	ret0, _ := ret[0].(error)
	return ret0
}

// Delete indicates an expected call of Delete
func (mr *MockTxDatabaseMockRecorder) Delete(id interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Delete", reflect.TypeOf((*MockTxDatabase)(nil).Delete), id)
}

// Query mocks base method
func (m *MockTxDatabase) Query(query *Query, accessControlOptions *AccessControlOptions) (*Rows, error) {
	ret := m.ctrl.Call(m, "Query", query, accessControlOptions)
	ret0, _ := ret[0].(*Rows)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Query indicates an expected call of Query
func (mr *MockTxDatabaseMockRecorder) Query(query, accessControlOptions interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Query", reflect.TypeOf((*MockTxDatabase)(nil).Query), query, accessControlOptions)
}

// QueryCount mocks base method
func (m *MockTxDatabase) QueryCount(query *Query, accessControlOptions *AccessControlOptions) (uint64, error) {
	ret := m.ctrl.Call(m, "QueryCount", query, accessControlOptions)
	ret0, _ := ret[0].(uint64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// QueryCount indicates an expected call of QueryCount
func (mr *MockTxDatabaseMockRecorder) QueryCount(query, accessControlOptions interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "QueryCount", reflect.TypeOf((*MockTxDatabase)(nil).QueryCount), query, accessControlOptions)
}

// Extend mocks base method
func (m *MockTxDatabase) Extend(recordType string, schema RecordSchema) (bool, error) {
	ret := m.ctrl.Call(m, "Extend", recordType, schema)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Extend indicates an expected call of Extend
func (mr *MockTxDatabaseMockRecorder) Extend(recordType, schema interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Extend", reflect.TypeOf((*MockTxDatabase)(nil).Extend), recordType, schema)
}

// RenameSchema mocks base method
func (m *MockTxDatabase) RenameSchema(recordType, oldColumnName, newColumnName string) error {
	ret := m.ctrl.Call(m, "RenameSchema", recordType, oldColumnName, newColumnName)
	ret0, _ := ret[0].(error)
	return ret0
}

// RenameSchema indicates an expected call of RenameSchema
func (mr *MockTxDatabaseMockRecorder) RenameSchema(recordType, oldColumnName, newColumnName interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RenameSchema", reflect.TypeOf((*MockTxDatabase)(nil).RenameSchema), recordType, oldColumnName, newColumnName)
}

// DeleteSchema mocks base method
func (m *MockTxDatabase) DeleteSchema(recordType, columnName string) error {
	ret := m.ctrl.Call(m, "DeleteSchema", recordType, columnName)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteSchema indicates an expected call of DeleteSchema
func (mr *MockTxDatabaseMockRecorder) DeleteSchema(recordType, columnName interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteSchema", reflect.TypeOf((*MockTxDatabase)(nil).DeleteSchema), recordType, columnName)
}

// GetSchema mocks base method
func (m *MockTxDatabase) GetSchema(recordType string) (RecordSchema, error) {
	ret := m.ctrl.Call(m, "GetSchema", recordType)
	ret0, _ := ret[0].(RecordSchema)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetSchema indicates an expected call of GetSchema
func (mr *MockTxDatabaseMockRecorder) GetSchema(recordType interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSchema", reflect.TypeOf((*MockTxDatabase)(nil).GetSchema), recordType)
}

// GetRecordSchemas mocks base method
func (m *MockTxDatabase) GetRecordSchemas() (map[string]RecordSchema, error) {
	ret := m.ctrl.Call(m, "GetRecordSchemas")
	ret0, _ := ret[0].(map[string]RecordSchema)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetRecordSchemas indicates an expected call of GetRecordSchemas
func (mr *MockTxDatabaseMockRecorder) GetRecordSchemas() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRecordSchemas", reflect.TypeOf((*MockTxDatabase)(nil).GetRecordSchemas))
}

// GetSubscription mocks base method
func (m *MockTxDatabase) GetSubscription(key, deviceID string, subscription *Subscription) error {
	ret := m.ctrl.Call(m, "GetSubscription", key, deviceID, subscription)
	ret0, _ := ret[0].(error)
	return ret0
}

// GetSubscription indicates an expected call of GetSubscription
func (mr *MockTxDatabaseMockRecorder) GetSubscription(key, deviceID, subscription interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSubscription", reflect.TypeOf((*MockTxDatabase)(nil).GetSubscription), key, deviceID, subscription)
}

// SaveSubscription mocks base method
func (m *MockTxDatabase) SaveSubscription(subscription *Subscription) error {
	ret := m.ctrl.Call(m, "SaveSubscription", subscription)
	ret0, _ := ret[0].(error)
	return ret0
}

// SaveSubscription indicates an expected call of SaveSubscription
func (mr *MockTxDatabaseMockRecorder) SaveSubscription(subscription interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveSubscription", reflect.TypeOf((*MockTxDatabase)(nil).SaveSubscription), subscription)
}

// DeleteSubscription mocks base method
func (m *MockTxDatabase) DeleteSubscription(key, deviceID string) error {
	ret := m.ctrl.Call(m, "DeleteSubscription", key, deviceID)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteSubscription indicates an expected call of DeleteSubscription
func (mr *MockTxDatabaseMockRecorder) DeleteSubscription(key, deviceID interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteSubscription", reflect.TypeOf((*MockTxDatabase)(nil).DeleteSubscription), key, deviceID)
}

// GetSubscriptionsByDeviceID mocks base method
func (m *MockTxDatabase) GetSubscriptionsByDeviceID(deviceID string) []Subscription {
	ret := m.ctrl.Call(m, "GetSubscriptionsByDeviceID", deviceID)
	ret0, _ := ret[0].([]Subscription)
	return ret0
}

// GetSubscriptionsByDeviceID indicates an expected call of GetSubscriptionsByDeviceID
func (mr *MockTxDatabaseMockRecorder) GetSubscriptionsByDeviceID(deviceID interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSubscriptionsByDeviceID", reflect.TypeOf((*MockTxDatabase)(nil).GetSubscriptionsByDeviceID), deviceID)
}

// GetMatchingSubscriptions mocks base method
func (m *MockTxDatabase) GetMatchingSubscriptions(record *Record) []Subscription {
	ret := m.ctrl.Call(m, "GetMatchingSubscriptions", record)
	ret0, _ := ret[0].([]Subscription)
	return ret0
}

// GetMatchingSubscriptions indicates an expected call of GetMatchingSubscriptions
func (mr *MockTxDatabaseMockRecorder) GetMatchingSubscriptions(record interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMatchingSubscriptions", reflect.TypeOf((*MockTxDatabase)(nil).GetMatchingSubscriptions), record)
}

// GetIndexesByRecordType mocks base method
func (m *MockTxDatabase) GetIndexesByRecordType(recordType string) (map[string]Index, error) {
	ret := m.ctrl.Call(m, "GetIndexesByRecordType", recordType)
	ret0, _ := ret[0].(map[string]Index)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetIndexesByRecordType indicates an expected call of GetIndexesByRecordType
func (mr *MockTxDatabaseMockRecorder) GetIndexesByRecordType(recordType interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetIndexesByRecordType", reflect.TypeOf((*MockTxDatabase)(nil).GetIndexesByRecordType), recordType)
}

// SaveIndex mocks base method
func (m *MockTxDatabase) SaveIndex(recordType, indexName string, index Index) error {
	ret := m.ctrl.Call(m, "SaveIndex", recordType, indexName, index)
	ret0, _ := ret[0].(error)
	return ret0
}

// SaveIndex indicates an expected call of SaveIndex
func (mr *MockTxDatabaseMockRecorder) SaveIndex(recordType, indexName, index interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SaveIndex", reflect.TypeOf((*MockTxDatabase)(nil).SaveIndex), recordType, indexName, index)
}

// DeleteIndex mocks base method
func (m *MockTxDatabase) DeleteIndex(recordType, indexName string) error {
	ret := m.ctrl.Call(m, "DeleteIndex", recordType, indexName)
	ret0, _ := ret[0].(error)
	return ret0
}

// DeleteIndex indicates an expected call of DeleteIndex
func (mr *MockTxDatabaseMockRecorder) DeleteIndex(recordType, indexName interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DeleteIndex", reflect.TypeOf((*MockTxDatabase)(nil).DeleteIndex), recordType, indexName)
}

// MockRowsIter is a mock of RowsIter interface
type MockRowsIter struct {
	ctrl     *gomock.Controller
	recorder *MockRowsIterMockRecorder
}

// MockRowsIterMockRecorder is the mock recorder for MockRowsIter
type MockRowsIterMockRecorder struct {
	mock *MockRowsIter
}

// NewMockRowsIter creates a new mock instance
func NewMockRowsIter(ctrl *gomock.Controller) *MockRowsIter {
	mock := &MockRowsIter{ctrl: ctrl}
	mock.recorder = &MockRowsIterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockRowsIter) EXPECT() *MockRowsIterMockRecorder {
	return m.recorder
}

// Close mocks base method
func (m *MockRowsIter) Close() error {
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close
func (mr *MockRowsIterMockRecorder) Close() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockRowsIter)(nil).Close))
}

// Next mocks base method
func (m *MockRowsIter) Next(record *Record) error {
	ret := m.ctrl.Call(m, "Next", record)
	ret0, _ := ret[0].(error)
	return ret0
}

// Next indicates an expected call of Next
func (mr *MockRowsIterMockRecorder) Next(record interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Next", reflect.TypeOf((*MockRowsIter)(nil).Next), record)
}

// OverallRecordCount mocks base method
func (m *MockRowsIter) OverallRecordCount() *uint64 {
	ret := m.ctrl.Call(m, "OverallRecordCount")
	ret0, _ := ret[0].(*uint64)
	return ret0
}

// OverallRecordCount indicates an expected call of OverallRecordCount
func (mr *MockRowsIterMockRecorder) OverallRecordCount() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OverallRecordCount", reflect.TypeOf((*MockRowsIter)(nil).OverallRecordCount))
}