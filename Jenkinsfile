pipeline {
    agent {
        label 'builder-backend-j8 || new-builder-backend-j8'
    }
    stages {
        stage('Build and Push Dependency Image') {
            steps {
                   sh "docker login -u='${ARTIFACTORY_CREDENTIALS_USR}' -p='${ARTIFACTORY_CREDENTIALS_PSW}' docker.internal.sysdig.com"
                   sh "IMAGE_TAG=${params.TAG} make -f makefile-sysdig build-dependency-image"
                   sh "IMAGE_TAG=${params.TAG} make -f makefile-sysdig push-dependency-image"
            }
            post {
                cleanup {
                   sh "IMAGE_TAG=${params.TAG} make -f makefile-sysdig delete-dependency-image"
                }
            }
        }
    }
}