pipeline {
    agent {
        label 'builder-backend-j8 || new-builder-backend-j8'
    }
    stages {
        stage('Build and Push Dependency Image') {
            steps {
                checkout([$class: 'GitSCM', branches: [[name: 'refs/tags/${params.TAG}']], doGenerateSubmoduleConfigurations: false, extensions: [], submoduleCfg: [], userRemoteConfigs: [[credentialsId: 'github-jenkins-user-token', url: 'https://github.com/draios/kube-bench']]])
                script {
                    docker.withRegistry("https://docker.internal.sysdig.com", 'jenkins-artifactory') {
                        sh "IMAGE_TAG=${params.TAG} make -f makefile-sysdig build-dependency-image"
                        sh "IMAGE_TAG=${params.TAG} make -f makefile-sysdig push-dependency-image"
                        sh "IMAGE_TAG=${params.TAG} make -f makefile-sysdig delete-dependency-image"
                    }
                }
            }
        }
    }
}