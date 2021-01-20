pipeline {
    agent {
        label 'builder-backend-j8 || new-builder-backend-j8'
    }
    stages {
        stage('Build and Push Dependency Image') {
            steps {
                checkout scm: [
                    $class: 'GitSCM',
                    userRemoteConfigs: [[
                        url: 'https://github.com/draios/kube-bench',
                        credentialsId: 'github-jenkins-user-token'
                    ]],
                    branches: [[name: 'refs/tags/${params.TAG}']]
                    ], poll: false
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