// Code generated by mockery. DO NOT EDIT.

package mock_l2_shared

import (
	context "context"

	l2_shared "github.com/0xPolygonHermez/zkevm-node/synchronizer/l2_sync/l2_shared"
	mock "github.com/stretchr/testify/mock"

	pgx "github.com/jackc/pgx/v4"
)

// SyncTrustedBatchExecutor is an autogenerated mock type for the SyncTrustedBatchExecutor type
type SyncTrustedBatchExecutor struct {
	mock.Mock
}

type SyncTrustedBatchExecutor_Expecter struct {
	mock *mock.Mock
}

func (_m *SyncTrustedBatchExecutor) EXPECT() *SyncTrustedBatchExecutor_Expecter {
	return &SyncTrustedBatchExecutor_Expecter{mock: &_m.Mock}
}

// FullProcess provides a mock function with given fields: ctx, data, dbTx
func (_m *SyncTrustedBatchExecutor) FullProcess(ctx context.Context, data *l2_shared.ProcessData, dbTx pgx.Tx) (*l2_shared.ProcessResponse, error) {
	ret := _m.Called(ctx, data, dbTx)

	if len(ret) == 0 {
		panic("no return value specified for FullProcess")
	}

	var r0 *l2_shared.ProcessResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *l2_shared.ProcessData, pgx.Tx) (*l2_shared.ProcessResponse, error)); ok {
		return rf(ctx, data, dbTx)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *l2_shared.ProcessData, pgx.Tx) *l2_shared.ProcessResponse); ok {
		r0 = rf(ctx, data, dbTx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*l2_shared.ProcessResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *l2_shared.ProcessData, pgx.Tx) error); ok {
		r1 = rf(ctx, data, dbTx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SyncTrustedBatchExecutor_FullProcess_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'FullProcess'
type SyncTrustedBatchExecutor_FullProcess_Call struct {
	*mock.Call
}

// FullProcess is a helper method to define mock.On call
//   - ctx context.Context
//   - data *l2_shared.ProcessData
//   - dbTx pgx.Tx
func (_e *SyncTrustedBatchExecutor_Expecter) FullProcess(ctx interface{}, data interface{}, dbTx interface{}) *SyncTrustedBatchExecutor_FullProcess_Call {
	return &SyncTrustedBatchExecutor_FullProcess_Call{Call: _e.mock.On("FullProcess", ctx, data, dbTx)}
}

func (_c *SyncTrustedBatchExecutor_FullProcess_Call) Run(run func(ctx context.Context, data *l2_shared.ProcessData, dbTx pgx.Tx)) *SyncTrustedBatchExecutor_FullProcess_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*l2_shared.ProcessData), args[2].(pgx.Tx))
	})
	return _c
}

func (_c *SyncTrustedBatchExecutor_FullProcess_Call) Return(_a0 *l2_shared.ProcessResponse, _a1 error) *SyncTrustedBatchExecutor_FullProcess_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *SyncTrustedBatchExecutor_FullProcess_Call) RunAndReturn(run func(context.Context, *l2_shared.ProcessData, pgx.Tx) (*l2_shared.ProcessResponse, error)) *SyncTrustedBatchExecutor_FullProcess_Call {
	_c.Call.Return(run)
	return _c
}

// IncrementalProcess provides a mock function with given fields: ctx, data, dbTx
func (_m *SyncTrustedBatchExecutor) IncrementalProcess(ctx context.Context, data *l2_shared.ProcessData, dbTx pgx.Tx) (*l2_shared.ProcessResponse, error) {
	ret := _m.Called(ctx, data, dbTx)

	if len(ret) == 0 {
		panic("no return value specified for IncrementalProcess")
	}

	var r0 *l2_shared.ProcessResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *l2_shared.ProcessData, pgx.Tx) (*l2_shared.ProcessResponse, error)); ok {
		return rf(ctx, data, dbTx)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *l2_shared.ProcessData, pgx.Tx) *l2_shared.ProcessResponse); ok {
		r0 = rf(ctx, data, dbTx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*l2_shared.ProcessResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *l2_shared.ProcessData, pgx.Tx) error); ok {
		r1 = rf(ctx, data, dbTx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SyncTrustedBatchExecutor_IncrementalProcess_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'IncrementalProcess'
type SyncTrustedBatchExecutor_IncrementalProcess_Call struct {
	*mock.Call
}

// IncrementalProcess is a helper method to define mock.On call
//   - ctx context.Context
//   - data *l2_shared.ProcessData
//   - dbTx pgx.Tx
func (_e *SyncTrustedBatchExecutor_Expecter) IncrementalProcess(ctx interface{}, data interface{}, dbTx interface{}) *SyncTrustedBatchExecutor_IncrementalProcess_Call {
	return &SyncTrustedBatchExecutor_IncrementalProcess_Call{Call: _e.mock.On("IncrementalProcess", ctx, data, dbTx)}
}

func (_c *SyncTrustedBatchExecutor_IncrementalProcess_Call) Run(run func(ctx context.Context, data *l2_shared.ProcessData, dbTx pgx.Tx)) *SyncTrustedBatchExecutor_IncrementalProcess_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*l2_shared.ProcessData), args[2].(pgx.Tx))
	})
	return _c
}

func (_c *SyncTrustedBatchExecutor_IncrementalProcess_Call) Return(_a0 *l2_shared.ProcessResponse, _a1 error) *SyncTrustedBatchExecutor_IncrementalProcess_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *SyncTrustedBatchExecutor_IncrementalProcess_Call) RunAndReturn(run func(context.Context, *l2_shared.ProcessData, pgx.Tx) (*l2_shared.ProcessResponse, error)) *SyncTrustedBatchExecutor_IncrementalProcess_Call {
	_c.Call.Return(run)
	return _c
}

// NothingProcess provides a mock function with given fields: ctx, data, dbTx
func (_m *SyncTrustedBatchExecutor) NothingProcess(ctx context.Context, data *l2_shared.ProcessData, dbTx pgx.Tx) (*l2_shared.ProcessResponse, error) {
	ret := _m.Called(ctx, data, dbTx)

	if len(ret) == 0 {
		panic("no return value specified for NothingProcess")
	}

	var r0 *l2_shared.ProcessResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *l2_shared.ProcessData, pgx.Tx) (*l2_shared.ProcessResponse, error)); ok {
		return rf(ctx, data, dbTx)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *l2_shared.ProcessData, pgx.Tx) *l2_shared.ProcessResponse); ok {
		r0 = rf(ctx, data, dbTx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*l2_shared.ProcessResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *l2_shared.ProcessData, pgx.Tx) error); ok {
		r1 = rf(ctx, data, dbTx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SyncTrustedBatchExecutor_NothingProcess_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'NothingProcess'
type SyncTrustedBatchExecutor_NothingProcess_Call struct {
	*mock.Call
}

// NothingProcess is a helper method to define mock.On call
//   - ctx context.Context
//   - data *l2_shared.ProcessData
//   - dbTx pgx.Tx
func (_e *SyncTrustedBatchExecutor_Expecter) NothingProcess(ctx interface{}, data interface{}, dbTx interface{}) *SyncTrustedBatchExecutor_NothingProcess_Call {
	return &SyncTrustedBatchExecutor_NothingProcess_Call{Call: _e.mock.On("NothingProcess", ctx, data, dbTx)}
}

func (_c *SyncTrustedBatchExecutor_NothingProcess_Call) Run(run func(ctx context.Context, data *l2_shared.ProcessData, dbTx pgx.Tx)) *SyncTrustedBatchExecutor_NothingProcess_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*l2_shared.ProcessData), args[2].(pgx.Tx))
	})
	return _c
}

func (_c *SyncTrustedBatchExecutor_NothingProcess_Call) Return(_a0 *l2_shared.ProcessResponse, _a1 error) *SyncTrustedBatchExecutor_NothingProcess_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *SyncTrustedBatchExecutor_NothingProcess_Call) RunAndReturn(run func(context.Context, *l2_shared.ProcessData, pgx.Tx) (*l2_shared.ProcessResponse, error)) *SyncTrustedBatchExecutor_NothingProcess_Call {
	_c.Call.Return(run)
	return _c
}

// ReProcess provides a mock function with given fields: ctx, data, dbTx
func (_m *SyncTrustedBatchExecutor) ReProcess(ctx context.Context, data *l2_shared.ProcessData, dbTx pgx.Tx) (*l2_shared.ProcessResponse, error) {
	ret := _m.Called(ctx, data, dbTx)

	if len(ret) == 0 {
		panic("no return value specified for ReProcess")
	}

	var r0 *l2_shared.ProcessResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *l2_shared.ProcessData, pgx.Tx) (*l2_shared.ProcessResponse, error)); ok {
		return rf(ctx, data, dbTx)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *l2_shared.ProcessData, pgx.Tx) *l2_shared.ProcessResponse); ok {
		r0 = rf(ctx, data, dbTx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*l2_shared.ProcessResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *l2_shared.ProcessData, pgx.Tx) error); ok {
		r1 = rf(ctx, data, dbTx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SyncTrustedBatchExecutor_ReProcess_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ReProcess'
type SyncTrustedBatchExecutor_ReProcess_Call struct {
	*mock.Call
}

// ReProcess is a helper method to define mock.On call
//   - ctx context.Context
//   - data *l2_shared.ProcessData
//   - dbTx pgx.Tx
func (_e *SyncTrustedBatchExecutor_Expecter) ReProcess(ctx interface{}, data interface{}, dbTx interface{}) *SyncTrustedBatchExecutor_ReProcess_Call {
	return &SyncTrustedBatchExecutor_ReProcess_Call{Call: _e.mock.On("ReProcess", ctx, data, dbTx)}
}

func (_c *SyncTrustedBatchExecutor_ReProcess_Call) Run(run func(ctx context.Context, data *l2_shared.ProcessData, dbTx pgx.Tx)) *SyncTrustedBatchExecutor_ReProcess_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*l2_shared.ProcessData), args[2].(pgx.Tx))
	})
	return _c
}

func (_c *SyncTrustedBatchExecutor_ReProcess_Call) Return(_a0 *l2_shared.ProcessResponse, _a1 error) *SyncTrustedBatchExecutor_ReProcess_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *SyncTrustedBatchExecutor_ReProcess_Call) RunAndReturn(run func(context.Context, *l2_shared.ProcessData, pgx.Tx) (*l2_shared.ProcessResponse, error)) *SyncTrustedBatchExecutor_ReProcess_Call {
	_c.Call.Return(run)
	return _c
}

// NewSyncTrustedBatchExecutor creates a new instance of SyncTrustedBatchExecutor. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewSyncTrustedBatchExecutor(t interface {
	mock.TestingT
	Cleanup(func())
}) *SyncTrustedBatchExecutor {
	mock := &SyncTrustedBatchExecutor{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
