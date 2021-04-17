package utils

import (
	"context"
	"github.com/SWRMLabs/ss-store"
	"math"
	r "math/rand"
	"sync"
	"time"
)

// For generating random strings
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	r.Seed(time.Now().Unix() + time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[r.Int63()%int64(len(letterBytes))]
	}
	return string(b)
}

type GetFactory func(string) store.Item

type result struct {
	index int
	val   store.Item
}

func FanOutGet(
	ctx context.Context,
	st store.Store,
	fanout int,
	ids []string,
	factory GetFactory,
	items []store.Item,
) (retErr error) {

	cctx, cancel := context.WithCancel(ctx)
	resultChan := make(chan result)
	errChan := make(chan error)
	wg := sync.WaitGroup{}

	defer close(resultChan)
	defer close(errChan)

	wg.Add(1)
	go func() {
		defer wg.Done()
		count := 0
		for {
			select {
			case <-cctx.Done():
				if ctx.Err() != nil {
					retErr = ctx.Err()
				}
				return
			case it, ok := <-resultChan:
				if !ok {
					return
				}
				items[it.index] = it.val
				count++
				if count == len(ids) {
					return
				}
			case e, ok := <-errChan:
				if ok && e != nil {
					retErr = e
				}
				cancel()
				return
			}
		}
	}()
	itemGroupCount := int(math.Ceil(float64(len(ids) / fanout)))
	for i := 0; i < fanout && (i*itemGroupCount < len(ids)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := i * itemGroupCount
			end := start + itemGroupCount
			if end > (len(ids) - 1) {
				end = len(ids) - 1
			}
			for idx, v := range ids[start:end] {
				select {
				case <-cctx.Done():
					return
				default:
				}
				it := factory(v)
				err := st.Read(it)
				if err != nil {
					errChan <- err
				} else {
					resultChan <- result{
						index: idx,
						val:   it,
					}
				}
			}
		}()
	}
	wg.Wait()
	return
}
