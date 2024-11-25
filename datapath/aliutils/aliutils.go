package aliutils

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/alibabacloud-go/darabonba-openapi/v2/client"
	sts "github.com/alibabacloud-go/sts-20150401/v2/client"
	"github.com/alibabacloud-go/tea/tea"
	stscredentials "github.com/aliyun/credentials-go/credentials"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/coreos/go-systemd/v22/journal"
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
	maxReqTimesPerSec   = 50
	reqChan             = make(chan stsReq, 1000)
	credMap             sync.Map
	aliStsRole          = "acs:ram::1450424585376992:role/cloud-desktop-test-oss"
	aliSessionName      = "cloud-desktop-test"
	stsClientRetryTime  = 7
	assumeRoleRetryTime = 3
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

func loadStsClient() (stsClient *sts.Client) {
	stsConf := new(stscredentials.Config).SetType("ecs_ram_role").SetRoleName("cloud-desktop-test-server")
	stsCredProvider, err := stscredentials.NewCredential(stsConf)
	if err != nil {
		journal.Print(journal.PriErr, "Failed to create sts client, check RAM role setting")
		os.Exit(1)
	}
	for i := 1; i <= stsClientRetryTime; i++ {
		t, err := stsCredProvider.GetCredential()
		if err != nil {
			time.Sleep((1 << (i - 1)) * time.Second)
			continue
		}
		stsClient, err = sts.NewClient(&client.Config{
			AccessKeyId:     t.AccessKeyId,
			AccessKeySecret: t.AccessKeySecret,
			SecurityToken:   t.SecurityToken,
			Endpoint:        aws.String("sts-vpc.cn-shanghai.aliyuncs.com"),
		})
		if err == nil {
			return
		}
	}
	journal.Print(journal.PriErr, "Failed to create sts client, check RAM role setting")
	os.Exit(1)
	return
}

func StartStsServer() {
	minStsReqIntvl := time.Second / time.Duration(maxReqTimesPerSec)
	var stsClient *sts.Client
	stsClient = loadStsClient()
	for {
		req := <-reqChan
		var res *sts.AssumeRoleResponse
		var err error
		for range assumeRoleRetryTime {
			res, err = stsClient.AssumeRole(&sts.AssumeRoleRequest{
				RoleArn:         aws.String(aliStsRole),
				RoleSessionName: aws.String(aliSessionName),
				DurationSeconds: aws.Int64(900),
				Policy:          aws.String(newPolicy(req.action, req.resource).ToString()),
			})
			if err != nil {
				if sdkErr, ok := err.(*tea.SDKError); ok && aws.ToString(sdkErr.Code) == "InvalidSecurityToken.Expired" {
					stsClient = loadStsClient()
				} else {
					journal.Print(journal.PriErr, "Unknown sts error: %v", err)
					os.Exit(1)
				}
			} else {
				break
			}
		}
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
