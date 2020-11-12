pipeline {
    agent any
    stages {
        stage('Build Agent tarball') {
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

                script{
                    withAWS(credentials: 'draios-dev-aws', region: 'us-east-1') {
                    s3Upload acl: 'PublicRead',
                             bucket: 'nkraemer',
                             file: "out/kube-bench-${params.TAG}.tar.gz",
                             path: "kube-bench-${params.TAG}.tar.gz"
                    }
                }
            }
            post {
                cleanup {
                    script {
                        sh("rm -rf out || /bin/true")
                        sh("docker system prune -f || /bin/true")
                    }
                }
            }
        }
    }
}
