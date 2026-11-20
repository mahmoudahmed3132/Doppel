// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"time"
)

// openTimedSQLite opens a sqlite *sql.DB whose queries and statements report
// their execution duration to observe (for doppel_db_query_seconds).
func openTimedSQLite(dsn string, observe func(time.Duration)) (*sql.DB, error) {
	if observe == nil {
		return sql.Open("sqlite", dsn)
	}
	base, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	drv := base.Driver()
	base.Close()
	return sql.OpenDB(&timedConnector{drv: drv, dsn: dsn, observe: observe}), nil
}

type timedConnector struct {
	drv     driver.Driver
	dsn     string
	observe func(time.Duration)
}

func (c *timedConnector) Connect(ctx context.Context) (driver.Conn, error) {
	var (
		conn driver.Conn
		err  error
	)
	if dc, ok := c.drv.(driver.DriverContext); ok {
		cc, cerr := dc.OpenConnector(c.dsn)
		if cerr != nil {
			return nil, cerr
		}
		conn, err = cc.Connect(ctx)
	} else {
		conn, err = c.drv.Open(c.dsn)
	}
	if err != nil {
		return nil, err
	}
	return &timedConn{Conn: conn, observe: c.observe}, nil
}

func (c *timedConnector) Driver() driver.Driver { return c.drv }

type timedConn struct {
	driver.Conn
	observe func(time.Duration)
}

func (c *timedConn) Ping(ctx context.Context) error {
	if p, ok := c.Conn.(driver.Pinger); ok {
		start := time.Now()
		err := p.Ping(ctx)
		c.observe(time.Since(start))
		return err
	}
	return nil
}

func (c *timedConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if b, ok := c.Conn.(driver.ConnBeginTx); ok {
		return b.BeginTx(ctx, opts)
	}
	return c.Conn.Begin() //nolint:staticcheck // fallback for legacy drivers
}

func (c *timedConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	var (
		st  driver.Stmt
		err error
	)
	if pc, ok := c.Conn.(driver.ConnPrepareContext); ok {
		st, err = pc.PrepareContext(ctx, query)
	} else {
		st, err = c.Conn.Prepare(query)
	}
	if err != nil {
		return nil, err
	}
	return &timedStmt{Stmt: st, observe: c.observe}, nil
}

func (c *timedConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if ec, ok := c.Conn.(driver.ExecerContext); ok {
		start := time.Now()
		res, err := ec.ExecContext(ctx, query, args)
		c.observe(time.Since(start))
		return res, err
	}
	return nil, driver.ErrSkip
}

func (c *timedConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if qc, ok := c.Conn.(driver.QueryerContext); ok {
		start := time.Now()
		rows, err := qc.QueryContext(ctx, query, args)
		c.observe(time.Since(start))
		return rows, err
	}
	return nil, driver.ErrSkip
}

type timedStmt struct {
	driver.Stmt
	observe func(time.Duration)
}

func (s *timedStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	if ec, ok := s.Stmt.(driver.StmtExecContext); ok {
		start := time.Now()
		res, err := ec.ExecContext(ctx, args)
		s.observe(time.Since(start))
		return res, err
	}
	return nil, driver.ErrSkip
}

func (s *timedStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	if qc, ok := s.Stmt.(driver.StmtQueryContext); ok {
		start := time.Now()
		rows, err := qc.QueryContext(ctx, args)
		s.observe(time.Since(start))
		return rows, err
	}
	return nil, driver.ErrSkip
}
