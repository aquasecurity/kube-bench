pipeline {
    agent {
        label 'builder-backend-j8 || new-builder-backend-j8'
    }
    stages {
        stage('Build and Push Dependency Image') {
            steps {
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