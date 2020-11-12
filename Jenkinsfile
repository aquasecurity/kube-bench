pipeline {
    agent {
        label 'builder-backend-j8 || new-builder-backend-j8'
    }
    stages {
        stage('Build tarball') {
            steps {
                   sh """
                   docker run \
                   --rm \
                   -e OUTPUT_FILENAME=kube-bench-${params.TAG} \
                   -v ${WORKSPACE}:/kube-bench \
                   -w /kube-bench \
                   golang \
                   bash build-tarball.sh
                   """
             }
        }
        stage('Push to S3') {
            steps {
                script{
                    withAWS(credentials: 'draios', region: 'us-east-1') {
                    s3Upload acl: 'PublicRead',
                             bucket: 'download.draios.com',
                             file: "out/kube-bench-${params.TAG}.tar.gz",
                             path: "dependencies/kube-bench-${params.TAG}.tar.gz"
                    }
                }
            }
            post {
                cleanup {
                    sh("rm -rf out || /bin/true")
                    sh("docker system prune -f || /bin/true")
                }
            }
        }
    }
}
