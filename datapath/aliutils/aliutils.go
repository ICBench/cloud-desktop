package aliutils

import (
	"datapath/utils"
	"encoding/json"
	"fmt"
	"math/rand"
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
	configPath                 = "/usr/local/etc/dataPathServer/aliConfig.toml"
)

var (
	maxReqTimesPerSec = 50
	reqChan           = make(chan stsReq, 1000)
	credMap           sync.Map
	stsRoleName       string
	ossRole           string
	sessionName       string
	endPoint          string
	maxRetryTimes     = 10
	maxRetrySec       = 60
	iniRetrySec       = 1
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
	Err             error
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

func loadStsClient() (*sts.Client, error) {
	stsConf := new(stscredentials.Config).SetType("ecs_ram_role").SetRoleName(stsRoleName)
	stsCredProvider, err := stscredentials.NewCredential(stsConf)
	if err != nil {
		return nil, err
	}
	var cred *stscredentials.CredentialModel
	maxDuration := iniRetrySec
	for i := 1; i <= maxRetryTimes; i++ {
		cred, err = stsCredProvider.GetCredential()
		if err != nil {
			if i == maxRetryTimes {
				return nil, err
			}
			maxDuration = min(maxDuration*2, maxRetrySec)
			sleepSec := rand.Intn(maxDuration/2) + maxDuration/2
			time.Sleep(time.Second * time.Duration(sleepSec))
			continue
		} else {
			break
		}
	}
	return sts.NewClient(&client.Config{
		AccessKeyId:     cred.AccessKeyId,
		AccessKeySecret: cred.AccessKeySecret,
		SecurityToken:   cred.SecurityToken,
		Endpoint:        aws.String(endPoint),
	})
}

func StartStsServer() {
	utils.LoadConfig(configPath, map[string]*string{
		"stsrolename": &stsRoleName,
		"ossrole":     &ossRole,
		"sessionname": &sessionName,
		"endpoint":    &endPoint,
	})
	minStsReqIntvl := time.Second / time.Duration(maxReqTimesPerSec)
	var stsClient *sts.Client = nil
	for {
		req := <-reqChan
		var res *sts.AssumeRoleResponse = nil
		var err error
		maxDuration := iniRetrySec
		for i := 1; i <= maxRetryTimes; i++ {
			if stsClient == nil {
				if i == maxRetryTimes {
					journal.Print(journal.PriErr, "Failed to load sts client")
					res = nil
					break
				}
				stsClient, err = loadStsClient()
				if err != nil {
					maxDuration = min(maxDuration*2, maxRetrySec)
					sleepSec := rand.Intn(maxDuration/2) + maxDuration/2
					time.Sleep(time.Second * time.Duration(sleepSec))
					continue
				}
			}
			res, err = stsClient.AssumeRole(&sts.AssumeRoleRequest{
				RoleArn:         aws.String(ossRole),
				RoleSessionName: aws.String(sessionName),
				DurationSeconds: aws.Int64(900),
				Policy:          aws.String(newPolicy(req.action, req.resource).ToString()),
			})
			if err != nil {
				if i == maxRetryTimes {
					journal.Print(journal.PriErr, "Unknown sts error: %v", err)
					res = nil
					break
				}
				if sdkErr, ok := err.(*tea.SDKError); ok && aws.ToString(sdkErr.Code) == "InvalidSecurityToken.Expired" {
					stsClient, _ = loadStsClient()
				}
				maxDuration = min(maxDuration*2, maxRetrySec)
				sleepSec := rand.Intn(maxDuration/2) + maxDuration/2
				time.Sleep(time.Second * time.Duration(sleepSec))
			} else {
				break
			}
		}
		var cred StsCred
		if res != nil {
			expTime, _ := time.Parse(time.RFC3339, aws.ToString(res.Body.Credentials.Expiration))
			cred = StsCred{
				AccessKeyId:     aws.ToString(res.Body.Credentials.AccessKeyId),
				AccessKeySecret: aws.ToString(res.Body.Credentials.AccessKeySecret),
				SecurityToken:   aws.ToString(res.Body.Credentials.SecurityToken),
				ExpTime:         expTime,
				Err:             nil,
			}
		} else {
			cred = StsCred{Err: fmt.Errorf("unknown ali server error")}
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

func GetStsCred(action string, appIdList []string, bucket string) (cred StsCred) {
	var actions, resource []string
	switch action {
	case ActionPutObject:
		ifce, exist := credMap.Load("putObjCred")
		if !exist || ifce.(StsCred).ExpTime.Add(-5*time.Minute).Before(time.Now()) {
			actions = []string{ActionPutObject, ActionAbortMultipartUpload, ActionListParts}
			cred = getStsCred(actions, []string{ResourceHead + "*"})
			if cred.Err != nil {
				credMap.Store("putObjCred", cred)
			}
		} else {
			cred = ifce.(StsCred)
		}
	case ActionGetObject:
		actions = []string{ActionGetObject}
		for _, id := range appIdList {
			resource = append(resource, ResourceHead+bucket+"/"+id+"/*")
		}
		cred = getStsCred(actions, resource)
	default:
		ifce, exist := credMap.Load("allCred")
		if !exist || ifce.(StsCred).ExpTime.Add(-5*time.Minute).Before(time.Now()) {
			actions = []string{ActionAll}
			cred = getStsCred(actions, []string{ResourceHead + "*"})
			if cred.Err != nil {
				credMap.Store("allCred", cred)
			}
		} else {
			cred = ifce.(StsCred)
		}
	}
	return
}
