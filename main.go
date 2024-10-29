package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func main() {
	profile := flag.String("profile", "", "AWS profile name to use")
	flag.Parse()

	ctx := context.Background()

	var cfg aws.Config
	var err error
	if *profile != "" {
		// プロファイルが指定された場合、そのプロファイルを使用
		cfg, err = config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(*profile))
	} else {
		// プロファイルが指定されない場合、デフォルト設定を使用
		cfg, err = config.LoadDefaultConfig(ctx)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "AWS設定を読み込めませんでした: %v\n", err)
		os.Exit(1)
	}

	client := iam.NewFromConfig(cfg)

	// 削除対象のポリシーを収集
	deleteArns, err := getPoliciesToDelete(ctx, client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ポリシーの取得中にエラーが発生しました: %v\n", err)
		os.Exit(1)
	}

	// 削除するポリシーを確認
	if len(deleteArns) == 0 {
		fmt.Println("削除するポリシーはありません。")
		os.Exit(0)
	}

	fmt.Println("以下のポリシーが削除されます:")
	for _, arn := range deleteArns {
		fmt.Println(arn)
	}

	fmt.Print("削除を続行しますか？ (y/n): ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input != "y" {
		fmt.Println("削除を中止します。")
		os.Exit(0)
	}

	// 削除を実行
	for _, policyArn := range deleteArns {
		err := deletePolicyVersions(ctx, client, policyArn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s のポリシーバージョンの削除中にエラーが発生しました: %v\n", policyArn, err)
			continue
		}

		fmt.Printf("ポリシーを削除しています: %s\n", policyArn)
		_, err = client.DeletePolicy(ctx, &iam.DeletePolicyInput{
			PolicyArn: aws.String(policyArn),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s のポリシー削除中にエラーが発生しました: %v\n", policyArn, err)
		}
	}

	fmt.Println("削除が正常に完了しました。")
}

func getPoliciesToDelete(ctx context.Context, client *iam.Client) ([]string, error) {
	var deleteArns []string
	var marker *string

	for {
		input := &iam.ListPoliciesInput{
			Scope:  types.PolicyScopeTypeLocal,
			Marker: marker,
		}

		output, err := client.ListPolicies(ctx, input)
		if err != nil {
			return nil, err
		}

		for _, policy := range output.Policies {
			if aws.ToInt32(policy.AttachmentCount) == 0 && aws.ToInt32(policy.PermissionsBoundaryUsageCount) == 0 {
				deleteArns = append(deleteArns, aws.ToString(policy.Arn))
			}
		}

		if output.IsTruncated {
			marker = output.Marker
		} else {
			break
		}
	}
	return deleteArns, nil
}

func deletePolicyVersions(ctx context.Context, client *iam.Client, policyArn string) error {
	input := &iam.ListPolicyVersionsInput{
		PolicyArn: aws.String(policyArn),
	}

	output, err := client.ListPolicyVersions(ctx, input)
	if err != nil {
		return err
	}

	for _, version := range output.Versions {
		if !aws.ToBool(&version.IsDefaultVersion) {
			versionId := aws.ToString(version.VersionId)
			fmt.Printf("ポリシーバージョンを削除しています: %s\n", versionId)
			_, err := client.DeletePolicyVersion(ctx, &iam.DeletePolicyVersionInput{
				PolicyArn: aws.String(policyArn),
				VersionId: aws.String(versionId),
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "ポリシーバージョン %s の削除中にエラーが発生しました: %v\n", versionId, err)
			}
		}
	}
	return nil
}
