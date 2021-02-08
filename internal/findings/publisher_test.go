package findings

import (
	"testing"

	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/aws/aws-sdk-go/service/securityhub/securityhubiface"
)

// Define a mock struct to be used in your unit tests of myFunc.
type MockSHClient struct {
	securityhubiface.SecurityHubAPI
	Batches         int
	NumberOfFinding int
}

func NewMockSHClient() *MockSHClient {
	return &MockSHClient{}
}

func (m *MockSHClient) BatchImportFindings(input *securityhub.BatchImportFindingsInput) (*securityhub.BatchImportFindingsOutput, error) {
	o := securityhub.BatchImportFindingsOutput{}
	m.Batches++
	m.NumberOfFinding = len(input.Findings)
	return &o, nil
}

func TestPublisher_publishFinding(t *testing.T) {
	type fields struct {
		client *MockSHClient
	}
	type args struct {
		finding []*securityhub.AwsSecurityFinding
	}
	tests := []struct {
		name             string
		fields           fields
		args             args
		wantBatchCount   int
		wantFindingCount int
	}{
		{"Test single finding", fields{NewMockSHClient()}, args{makeFindings(1)}, 1, 1},
		{"Test 150 finding should return 2 batches", fields{NewMockSHClient()}, args{makeFindings(150)}, 2, 150},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(tt.fields.client)
			p.PublishFinding(tt.args.finding)
			if tt.fields.client.NumberOfFinding != tt.wantFindingCount {
				t.Errorf("Publisher.publishFinding() want = %v, got %v", tt.wantFindingCount, tt.fields.client.NumberOfFinding)
			}
			if tt.fields.client.Batches != tt.wantBatchCount {
				t.Errorf("Publisher.publishFinding() want = %v, got %v", tt.wantBatchCount, tt.fields.client.Batches)
			}
		})
	}
}

func makeFindings(count int) []*securityhub.AwsSecurityFinding {
	var findings []*securityhub.AwsSecurityFinding

	for i := 0; i < count; i++ {
		t := securityhub.AwsSecurityFinding{}
		findings = append(findings, &t)

	}
	return findings
}
