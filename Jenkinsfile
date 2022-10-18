pipeline {
    agent {
        label 'amazon-linux2'
    }
    parameters {
        gitParameter name: 'TAG',
                     type: 'PT_TAG',
                     defaultValue: 'master'
    }
    stages {
        stage('Build and Push Dependency Image') {
            steps {
                checkout([$class: 'GitSCM',
                    branches: [[name: "${params.TAG}"]],
                    doGenerateSubmoduleConfigurations: false,
                    extensions: [],
                    submoduleCfg: [],
                    userRemoteConfigs: [[credentialsId: 'github-jenkins-user-token', url: 'https://github.com/draios/kube-bench.git']]
                ])
                script {
                    docker.withRegistry("https://docker.internal.sysdig.com", 'jenkins-artifactory') {
                        sh "IMAGE_TAG=${params.TAG} PUSH=yes make -f makefile-sysdig build-dependency-image"
                    }
                }
            }
        }
    }
}