pipeline {
    agent {
        label 'amazon-linux2'
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
                        sh '''
                            echo "Logging into GAR dev"
                            cat $GAR_WR_SECRET | docker login --username _json_key --password-stdin us-docker.pkg.dev/sysdig-artifact-registry-dev/gar-docker
                            
                            IMAGE_TAG=${params.TAG} PUSH=yes make -f makefile-sysdig build-dependency-image
                        '''
                    }
                }
            }
        }
    }
}
