/*
Copyright 2020 The Knative Authors
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package handler

import (
	"net/http"
	"strconv"

	pkghttp "knative.dev/serving/pkg/http"
	"k8s.io/apimachinery/pkg/types"
	"knative.dev/serving/pkg/activator"
)

// NewAsyncDoneHandler creates a handler that sends ReqOut events to
// the given channel.
func NewAsyncDoneHandler(reqChan chan ReqEvent, next http.Handler) *AsyncDoneHandler {
	handler := &AsyncDoneHandler{
		nextHandler: next,
		ReqChan:     reqChan,
	}

	return handler
}

// AsyncDoneHandler sends events to the given channel.
type AsyncDoneHandler struct {
	nextHandler http.Handler
	ReqChan     chan ReqEvent
}

func (h *AsyncDoneHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var isAsync bool
	asyncHeader := r.Header.Get("Async-Done")
	if asyncHeader != "" {
		isAsync, _ = strconv.ParseBool(asyncHeader)
	}

	if !isAsync {
		recorder := pkghttp.NewResponseRecorder(w, http.StatusOK)
		h.nextHandler.ServeHTTP(recorder, r)
		return
	}

	revisionKey := types.NamespacedName{
		r.Header.Get(activator.RevisionHeaderNamespace),
		r.Header.Get(activator.RevisionHeaderName),
	}
	h.ReqChan <- ReqEvent{Key: revisionKey, EventType: ReqOut}
}
