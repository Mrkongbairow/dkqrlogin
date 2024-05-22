package main

import (
	"sync"
	"time"
)

type TTLCache struct {
	m sync.Map
}

type cacheEntity struct {
	dl time.Time
	v  interface{}
}

func NewTTL() *TTLCache {
	return &TTLCache{}
}

func (c *TTLCache) Load(key interface{}) interface{} {
	v, loaded := c.m.Load(key)
	if !loaded {
		return nil
	}
	cv := v.(cacheEntity)
	if time.Now().After(cv.dl) {
		c.m.Delete(key)
		return nil
	}
	return cv.v
}

func (c *TTLCache) Store(key, value interface{}, ttl time.Duration) {
	if value == nil {
		panic("can not store nil into ttl_cache")
	}
	c.m.Store(key, cacheEntity{
		dl: time.Now().Add(ttl),
		v:  value,
	})
}
