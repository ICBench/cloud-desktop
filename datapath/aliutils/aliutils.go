package aliutils

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/alibabacloud-go/darabonba-openapi/v2/client"
	sts "github.com/alibabacloud-go/sts-20150401/v2/client"
	stscredentials "github.com/aliyun/credentials-go/credentials"
	"github.com/aws/aws-sdk-go-v2/aws"
)

const (
	ActionGetObject            = "oss:GetObject"
	ActionPutObject            = "oss:PutObject"
	ActionDeleteObject         = "oss:DeleteObject"
	ActionAbortMultipartUpload = "oss:AbortMultipartUpload"
	ActionListParts            = "oss:ListParts"
	ActionAll                  = "oss:*"
	ResourceHead               = "acs:oss:*:*:"
)

var (
	maxReqTimesPerSec = 50
	reqChan           = make(chan stsReq, 1000)
	maxStsClientTime  = 50 * time.Minute
	credMap           sync.Map
)

type stsReq struct {
	action, resource []string
	resChan          chan StsCred
}

type StsCred struct {
	AccessKeyId     string
	AccessKeySecret string
	SecurityToken   string
	ExpTime         time.Time
}

type state struct {
	Effect   string
	Action   []string
	Resource []string
}

type policy struct {
	Version   string
	Statement []state
}

func newPolicy(action []string, resource []string) (p *policy) {
	p = new(policy)
	p.Version = "1"
	p.Statement = append(p.Statement, state{Effect: "Allow", Action: action, Resource: resource})
	return
}

func (p policy) ToString() string {
	jsonBytes, _ := json.Marshal(p)
	return string(jsonBytes)
}

func startStsServer() {
	minStsReqIntvl := time.Second / time.Duration(maxReqTimesPerSec)
	var mu sync.Mutex
	var stsClient *sts.Client
	go func() {
		for {
			stsConf := new(stscredentials.Config).SetType("ecs_ram_role")
			stsCredProvider, _ := stscredentials.NewCredential(stsConf)
			t, _ := stsCredProvider.GetCredential()
			mu.Lock()
			stsClient, _ = sts.NewClient(&client.Config{
				AccessKeyId:     t.AccessKeyId,
				AccessKeySecret: t.AccessKeySecret,
				SecurityToken:   t.SecurityToken,
				Endpoint:        aws.String("sts-vpc.cn-shanghai.aliyuncs.com"),
			})
			mu.Unlock()
			time.Sleep(maxStsClientTime)
		}
	}()
	time.Sleep(time.Second * 5)
	for {
		req := <-reqChan
		mu.Lock()
		res, _ := stsClient.AssumeRole(&sts.AssumeRoleRequest{
			RoleArn:         aws.String("acs:ram::1450424585376992:role/cloud-desktop"),
			RoleSessionName: aws.String("cloud-desktop-test"),
			DurationSeconds: aws.Int64(900),
			Policy:          aws.String(newPolicy(req.action, req.resource).ToString()),
		})
		mu.Unlock()
		expTime, _ := time.Parse(time.RFC3339, aws.ToString(res.Body.Credentials.Expiration))
		cred := StsCred{
			AccessKeyId:     aws.ToString(res.Body.Credentials.AccessKeyId),
			AccessKeySecret: aws.ToString(res.Body.Credentials.AccessKeySecret),
			SecurityToken:   aws.ToString(res.Body.Credentials.SecurityToken),
			ExpTime:         expTime,
		}
		req.resChan <- cred
		time.Sleep(minStsReqIntvl)
	}
}

func StartStsServer() {
	go func() {
		startStsServer()
	}()
}

func getStsCred(action, resource []string) StsCred {
	resChan := make(chan StsCred, 1)
	req := stsReq{
		action:   action,
		resource: resource,
		resChan:  resChan,
	}
	reqChan <- req
	return <-resChan
}

func GetStsCred(action string, hashList []string, bucket string) (cred StsCred) {
	var actions, resource []string
	switch action {
	case ActionPutObject:
		ifce, exist := credMap.Load("putObjCred")
		if !exist || ifce.(StsCred).ExpTime.Add(-5*time.Minute).Before(time.Now()) {
			actions = []string{ActionPutObject, ActionAbortMultipartUpload, ActionListParts}
			cred = getStsCred(actions, []string{ResourceHead + "*"})
			credMap.Store("putObjCred", cred)
		} else {
			cred = ifce.(StsCred)
		}
	case ActionGetObject:
		actions = []string{ActionGetObject}
		for _, hash := range hashList {
			resource = append(resource, ResourceHead+bucket+"/"+hash)
		}
		cred = getStsCred(actions, resource)
	default:
		ifce, exist := credMap.Load("allCred")
		if !exist || ifce.(StsCred).ExpTime.Add(-5*time.Minute).Before(time.Now()) {
			actions = []string{ActionAll}
			cred = getStsCred(actions, []string{ResourceHead + "*"})
			credMap.Store("allCred", cred)
		} else {
			cred = ifce.(StsCred)
		}
	}
	return
}