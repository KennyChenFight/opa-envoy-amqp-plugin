// Copyright 2018 The OPA Authors.  All rights reserved.
// Use of this source code is governed by an Apache2
// license that can be found in the LICENSE file.

package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KennyChenFight/golib/amqplib"

	ext_core_v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	ext_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	ext_authz_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	ext_type_v2 "github.com/envoyproxy/go-control-plane/envoy/type"
	ext_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/rpc/code"
	rpc_status "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/KennyChenFight/opa-envoy-amqp-plugin/envoyauth"
	internal_util "github.com/KennyChenFight/opa-envoy-amqp-plugin/internal/util"
	"github.com/KennyChenFight/opa-envoy-amqp-plugin/opa/decisionlog"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/server"
	"github.com/open-policy-agent/opa/storage"
	iCache "github.com/open-policy-agent/opa/topdown/cache"
	"github.com/open-policy-agent/opa/util"
)

const defaultAddr = ":9191"
const defaultPath = "envoy/authz/allow"
const defaultDryRun = false
const defaultEnableReflection = false

// PluginName is the name to register with the OPA plugin manager
const PluginName = "envoy_ext_authz_grpc"

// Validate receives a slice of bytes representing the plugin's
// configuration and returns a configuration value that can be used to
// instantiate the plugin.
func Validate(m *plugins.Manager, bs []byte) (*Config, error) {

	cfg := Config{
		Addr:             defaultAddr,
		DryRun:           defaultDryRun,
		EnableReflection: defaultEnableReflection,
	}

	if err := util.Unmarshal(bs, &cfg); err != nil {
		return nil, err
	}

	if cfg.Path != "" && cfg.Query != "" {
		return nil, fmt.Errorf("invalid config: specify a value for only the \"path\" field")
	}

	var parsedQuery ast.Body
	var err error

	if cfg.Query != "" {
		// Deprecated: Use Path instead
		parsedQuery, err = ast.ParseBody(cfg.Query)
	} else {
		if cfg.Path == "" {
			cfg.Path = defaultPath
		}
		path := stringPathToDataRef(cfg.Path)
		parsedQuery, err = ast.ParseBody(path.String())
	}

	if err != nil {
		return nil, err
	}

	cfg.parsedQuery = parsedQuery

	if cfg.ProtoDescriptor != "" {
		ps, err := internal_util.ReadProtoSet(cfg.ProtoDescriptor)
		if err != nil {
			return nil, err
		}
		cfg.protoSet = ps
	}

	return &cfg, nil
}

// New returns a Plugin that implements the Envoy ext_authz API.
func New(m *plugins.Manager, cfg *Config) plugins.Plugin {
	var plugin *envoyExtAuthzGrpcServer

	connectionConfig := &amqplib.AMQPConnectionConfig{
		URL:          cfg.AMQPUrl,
		ErrorHandler: nil,
	}

	if os.Getenv("APPLICATION_NAME") == "" {
		logrus.WithField("err", errors.New("env APPLICATION_NAME is empty")).Fatal("Unable to create amqpConsumer.")
	}

	queueConfig := &amqplib.AMQPQueueConfig{
		ExchangeName:        cfg.ExchangeName,
		ExchangeType:        amqplib.ExchangeType(cfg.ExchangeType),
		AutoDeclareExchange: false,
		QueueName:           os.Getenv("APPLICATION_NAME"),
		RoutingKey:          cfg.RouterKey,
		AutoDelete:          false,
	}
	client := amqplib.NewAMQPClient(connectionConfig)
	consumer, err := client.NewConsumer(queueConfig)
	if err != nil {
		logrus.WithField("err", err).Fatal("Unable to create amqpConsumer.")
	}

	plugin = &envoyExtAuthzGrpcServer{
		manager:                m,
		cfg:                    *cfg,
		server:                 grpc.NewServer(),
		preparedQueryDoOnce:    new(sync.Once),
		interQueryBuiltinCache: iCache.NewInterQueryCache(m.InterQueryBuiltinCacheConfig()),

		amqpClient:   client,
		amqpConsumer: consumer,
	}

	// Register Authorization Server
	ext_authz_v3.RegisterAuthorizationServer(plugin.server, plugin)
	ext_authz_v2.RegisterAuthorizationServer(plugin.server, &envoyExtAuthzV2Wrapper{v3: plugin})

	m.RegisterCompilerTrigger(plugin.compilerUpdated)

	// Register reflection service on gRPC server
	if cfg.EnableReflection {
		reflection.Register(plugin.server)
	}

	m.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})

	return plugin
}

// Config represents the plugin configuration.
type Config struct {
	Addr             string `json:"addr"`
	Query            string `json:"query"` // Deprecated: Use Path instead
	Path             string `json:"path"`
	DryRun           bool   `json:"dry-run"`
	EnableReflection bool   `json:"enable-reflection"`
	parsedQuery      ast.Body
	ProtoDescriptor  string `json:"proto-descriptor"`
	protoSet         *protoregistry.Files

	AMQPUrl      string `json:"amqpUrl"`
	ExchangeName string `json:"exchangeName"`
	ExchangeType string `json:"exchangeType"`
	RouterKey    string `json:"routerKey"`
}

type envoyExtAuthzGrpcServer struct {
	cfg                    Config
	server                 *grpc.Server
	manager                *plugins.Manager
	preparedQuery          *rego.PreparedEvalQuery
	preparedQueryDoOnce    *sync.Once
	interQueryBuiltinCache iCache.InterQueryCache
	amqpClient             *amqplib.AMQPClient
	amqpConsumer           amqplib.Consumer
}

type envoyExtAuthzV2Wrapper struct {
	v3 *envoyExtAuthzGrpcServer
}

func (p *envoyExtAuthzGrpcServer) ParsedQuery() ast.Body {
	return p.cfg.parsedQuery
}

func (p *envoyExtAuthzGrpcServer) Store() storage.Store {
	return p.manager.Store
}

func (p *envoyExtAuthzGrpcServer) Compiler() *ast.Compiler {
	return p.manager.GetCompiler()
}

func (p *envoyExtAuthzGrpcServer) Runtime() *ast.Term {
	return p.manager.Info
}

func (p *envoyExtAuthzGrpcServer) PreparedQueryDoOnce() *sync.Once {
	return p.preparedQueryDoOnce
}

func (p *envoyExtAuthzGrpcServer) InterQueryBuiltinCache() iCache.InterQueryCache {
	return p.interQueryBuiltinCache
}

func (p *envoyExtAuthzGrpcServer) PreparedQuery() *rego.PreparedEvalQuery {
	return p.preparedQuery
}

func (p *envoyExtAuthzGrpcServer) SetPreparedQuery(pq *rego.PreparedEvalQuery) {
	p.preparedQuery = pq
}

func (p *envoyExtAuthzGrpcServer) Start(ctx context.Context) error {
	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})
	go p.listen()
	go p.consume()
	go func() {
		time.Sleep(10 * time.Second)
		if err := p.getAndUpdateLatestPolicy(); err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
			}).Error("getAndUpdateLatestPolicy fail.")
		}
	}()
	return nil
}

func (p *envoyExtAuthzGrpcServer) Stop(ctx context.Context) {
	p.server.Stop()
	p.amqpConsumer.Close()
	p.amqpClient.Close()
	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})
}

func (p *envoyExtAuthzGrpcServer) Reconfigure(ctx context.Context, config interface{}) {
	return
}

func (p *envoyExtAuthzGrpcServer) compilerUpdated(txn storage.Transaction) {
	p.preparedQueryDoOnce = new(sync.Once)
}

func (p *envoyExtAuthzGrpcServer) listen() {
	// The listener is closed automatically by Serve when it returns.
	l, err := net.Listen("tcp", p.cfg.Addr)
	if err != nil {
		logrus.WithField("err", err).Fatal("Unable to create listener.")
	}

	logrus.WithFields(logrus.Fields{
		"addr":              p.cfg.Addr,
		"query":             p.cfg.Query,
		"path":              p.cfg.Path,
		"dry-run":           p.cfg.DryRun,
		"enable-reflection": p.cfg.EnableReflection,
	}).Info("Starting gRPC server.")

	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateOK})

	if err := p.server.Serve(l); err != nil {
		logrus.WithField("err", err).Fatal("Listener failed.")
	}

	logrus.Info("Listener exited.")
	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})
}

func (p *envoyExtAuthzGrpcServer) consume() {
	logrus.WithFields(logrus.Fields{
		"queueName": os.Getenv("APPLICATION_NAME"),
	}).Info("Starting amqp consumer")

	for delivery := range p.amqpConsumer.Consume() {
		logrus.WithFields(logrus.Fields{
			"deliveryBody": string(delivery.Body),
		}).Info("Consume.")
		if err := p.updatePolicy(delivery.Body); err != nil {
			logrus.WithField("err", err).Error("Unable to update policy.")
		}
		delivery.Ack(false)
	}
}

func (p *envoyExtAuthzGrpcServer) updatePolicy(body []byte) error {
	var content = make(map[string]string)
	if err := json.Unmarshal(body, &content); err != nil {
		return err
	}
	if !strings.Contains(os.Getenv("APPLICATION_NAME"), content["applicationName"]) {
		logrus.WithFields(logrus.Fields{"messageApplicationName": content["applicationName"], "envApplicationName": os.Getenv("APPLICATION_NAME")}).Error("Not my policy.")
		return nil
	}

	client := http.DefaultClient
	requestBody := bytes.NewBufferString(content["content"])
	req, err := http.NewRequest(http.MethodPut, "http://localhost:8181/v1/policies/%2Fpolicy%2Fpolicy.rego", requestBody)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(res.Body)
		return fmt.Errorf("fail update policy: statusCode:%d resp:%s", res.StatusCode, string(body))
	}

	req, err = http.NewRequest(http.MethodGet, "http://localhost:8181/v1/policies/%2Fpolicy%2Fpolicy.rego", nil)
	if err != nil {
		return err
	}
	res, err = client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	body, _ = ioutil.ReadAll(res.Body)
	fmt.Println("fuck:", string(body))
	fmt.Println("fuck2:", res.StatusCode)

	return nil
}

// Check is envoy.service.auth.v3.Authorization/Check
func (p *envoyExtAuthzGrpcServer) Check(ctx context.Context, req *ext_authz_v3.CheckRequest) (*ext_authz_v3.CheckResponse, error) {
	resp, stop, err := p.check(ctx, req)
	if code := stop(); resp != nil && code != nil {
		resp.Status = code
	}
	return resp, err
}

func (p *envoyExtAuthzGrpcServer) check(ctx context.Context, req interface{}) (*ext_authz_v3.CheckResponse, func() *rpc_status.Status, error) {
	var err error
	start := time.Now()

	result, stopeval, err := envoyauth.NewEvalResult()
	if err != nil {
		logrus.WithField("err", err).Error("Unable to start new evaluation.")
		return nil, func() *rpc_status.Status { return nil }, err
	}
	logEntry := logrus.WithField("decision-id", result.DecisionID)

	var input map[string]interface{}

	stop := func() *rpc_status.Status {
		stopeval()
		logErr := p.log(ctx, input, result, err)
		if logErr != nil {
			return &rpc_status.Status{
				Code:    int32(code.Code_UNKNOWN),
				Message: logErr.Error(),
			}
		}
		return nil
	}

	if ctx.Err() != nil {
		err = errors.Wrap(ctx.Err(), "check request timed out before query execution")
		return nil, stop, err
	}

	input, err = envoyauth.RequestToInput(req, logEntry, p.cfg.protoSet)
	if err != nil {
		return nil, stop, err
	}

	inputValue, err := ast.InterfaceToValue(input)
	if err != nil {
		return nil, stop, err
	}

	err = envoyauth.Eval(ctx, p, inputValue, result)
	if err != nil {
		return nil, stop, err
	}

	resp := &ext_authz_v3.CheckResponse{}

	allowed, err := result.IsAllowed()

	if err != nil {
		return nil, stop, errors.Wrap(err, "failed to get response status")
	}

	status := int32(code.Code_PERMISSION_DENIED)
	if allowed {
		status = int32(code.Code_OK)
	}
	resp.Status = &rpc_status.Status{Code: status}

	switch result.Decision.(type) {
	case map[string]interface{}:
		responseHeaders, err := result.GetResponseEnvoyHeaderValueOptions()
		if err != nil {
			return nil, stop, errors.Wrap(err, "failed to get response headers")
		}

		if status == int32(code.Code_OK) {
			resp.HttpResponse = &ext_authz_v3.CheckResponse_OkResponse{
				OkResponse: &ext_authz_v3.OkHttpResponse{
					Headers: responseHeaders,
				},
			}
		} else {
			body, err := result.GetResponseBody()
			if err != nil {
				return nil, stop, errors.Wrap(err, "failed to get response body")
			}

			httpStatus, err := result.GetResponseEnvoyHTTPStatus()
			if err != nil {
				return nil, stop, errors.Wrap(err, "failed to get response http status")
			}

			deniedResponse := &ext_authz_v3.DeniedHttpResponse{
				Headers: responseHeaders,
				Body:    body,
				Status:  httpStatus,
			}

			resp.HttpResponse = &ext_authz_v3.CheckResponse_DeniedResponse{
				DeniedResponse: deniedResponse,
			}
		}
	}

	logrus.WithFields(logrus.Fields{
		"query":               p.cfg.parsedQuery.String(),
		"dry-run":             p.cfg.DryRun,
		"decision":            result.Decision,
		"err":                 err,
		"txn":                 result.TxnID,
		"metrics":             result.Metrics.All(),
		"total_decision_time": time.Since(start),
	}).Debug("Returning policy decision.")

	// If dry-run mode, override the Status code to unconditionally Allow the request
	// DecisionLogging should reflect what "would" have happened
	if p.cfg.DryRun {
		if resp.Status.Code != int32(code.Code_OK) {
			resp.Status = &rpc_status.Status{Code: int32(code.Code_OK)}
			resp.HttpResponse = &ext_authz_v3.CheckResponse_OkResponse{
				OkResponse: &ext_authz_v3.OkHttpResponse{},
			}
		}
	}

	return resp, stop, nil
}

func (p *envoyExtAuthzGrpcServer) log(ctx context.Context, input interface{}, result *envoyauth.EvalResult, err error) error {
	info := &server.Info{
		Timestamp: time.Now(),
		Input:     &input,
	}

	if p.cfg.Query != "" {
		info.Query = p.cfg.Query
	}

	if p.cfg.Path != "" {
		info.Path = p.cfg.Path
	}

	return decisionlog.LogDecision(ctx, p.manager, info, result, err)
}

func (p *envoyExtAuthzGrpcServer) getAndUpdateLatestPolicy() error {
	if os.Getenv("APPLICATION_NAME") == "" {
		return errors.New("APPLICATION_NAME env can not be empty string")
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://policy-register/v1/application/policies/%s", os.Getenv("APPLICATION_NAME")), nil)
	if err != nil {
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	logrus.WithFields(logrus.Fields{
		"response statusCode": res.StatusCode,
	}).Info("getAndUpdateLatestPolicy response statusCode.")
	if res.StatusCode == http.StatusOK {
		b, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}
		logrus.WithFields(logrus.Fields{
			"response body": string(b),
		}).Info("getAndUpdateLatestPolicy response body.")
		return p.updatePolicy(b)
	} else if res.StatusCode == http.StatusBadRequest {
		logrus.Info("getAndUpdateLatestPolicy can not find forward")
		return errors.New("can not find forward")
	}
	return nil
}

func stringPathToDataRef(s string) (r ast.Ref) {
	result := ast.Ref{ast.DefaultRootDocument}
	result = append(result, stringPathToRef(s)...)
	return result
}

func stringPathToRef(s string) (r ast.Ref) {
	if len(s) == 0 {
		return r
	}

	p := strings.Split(s, "/")
	for _, x := range p {
		if x == "" {
			continue
		}

		i, err := strconv.Atoi(x)
		if err != nil {
			r = append(r, ast.StringTerm(x))
		} else {
			r = append(r, ast.IntNumberTerm(i))
		}
	}
	return r
}

// Check is envoy.service.auth.v2.Authorization/Check
func (p *envoyExtAuthzV2Wrapper) Check(ctx context.Context, req *ext_authz_v2.CheckRequest) (*ext_authz_v2.CheckResponse, error) {
	var stop func() *rpc_status.Status
	respV2 := &ext_authz_v2.CheckResponse{}
	respV3, stop, err := p.v3.check(ctx, req)
	defer func() {
		if code := stop(); code != nil {
			respV2.Status = code
		}
	}()

	if err != nil {
		return nil, err
	}
	respV2 = v2Response(respV3)
	return respV2, nil
}

func v2Response(respV3 *ext_authz_v3.CheckResponse) *ext_authz_v2.CheckResponse {
	respV2 := ext_authz_v2.CheckResponse{
		Status: respV3.Status,
	}
	switch http3 := respV3.HttpResponse.(type) {
	case *ext_authz_v3.CheckResponse_OkResponse:
		hdrs := http3.OkResponse.GetHeaders()
		respV2.HttpResponse = &ext_authz_v2.CheckResponse_OkResponse{
			OkResponse: &ext_authz_v2.OkHttpResponse{
				Headers: v2Headers(hdrs),
			}}
	case *ext_authz_v3.CheckResponse_DeniedResponse:
		hdrs := http3.DeniedResponse.GetHeaders()
		respV2.HttpResponse = &ext_authz_v2.CheckResponse_DeniedResponse{
			DeniedResponse: &ext_authz_v2.DeniedHttpResponse{
				Headers: v2Headers(hdrs),
				Status:  v2Status(http3.DeniedResponse.Status),
				Body:    http3.DeniedResponse.Body,
			}}
	}
	return &respV2
}

func v2Headers(hdrs []*ext_core_v3.HeaderValueOption) []*ext_core_v2.HeaderValueOption {
	hdrsV2 := make([]*ext_core_v2.HeaderValueOption, len(hdrs))
	for i, hv := range hdrs {
		hdrsV2[i] = &ext_core_v2.HeaderValueOption{
			Header: &ext_core_v2.HeaderValue{
				Key:   hv.GetHeader().Key,
				Value: hv.GetHeader().Value,
			},
		}
	}
	return hdrsV2
}

func v2Status(s *ext_type_v3.HttpStatus) *ext_type_v2.HttpStatus {
	return &ext_type_v2.HttpStatus{
		Code: ext_type_v2.StatusCode(s.Code),
	}
}
