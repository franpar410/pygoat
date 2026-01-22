node {

    def APP_NAME    = "PyGoat"
    def APP_VERSION = "1.0"

    try {

        stage('Checkout SCM') {
            checkout scm
        }

        stage('SAST - Bandit') {
            echo "Running Bandit SAST analysis"

            sh '''
            docker run --rm \
              -v "$PWD":/src \
              -w /src \
              python:3.11-slim \
              sh -c "
                pip install --no-cache-dir bandit && \
                bandit -r . \
                       -f json \
                       -o bandit-report.json \
                       --exit-zero
              "
            '''
        }

        stage('Upload Bandit to DefectDojo') {
            withCredentials([
                string(credentialsId: 'DEFECTDOJO_API_KEY', variable: 'DD_API_KEY'),
                string(credentialsId: 'DEFECTDOJO_URL',     variable: 'DD_URL')
            ]) {

                sh '''
                echo "Uploading Bandit report to DefectDojo..."

                curl -s -X POST "$DD_URL/api/v2/import-scan/" \
                  -H "Authorization: Token $DD_API_KEY" \
                  -F "scan_type=Bandit Scan" \
                  -F "product_name=PyGoat" \
                  -F "engagement_name=PyGoat CI/CD" \
                  -F "minimum_severity=Low" \
                  -F "active=true" \
                  -F "verified=false" \
                  -F "close_old_findings=false" \
                  -F "file=@bandit-report.json"
                '''
            }
        }

        stage('Security Gate - Bandit') {
            echo "Evaluating Bandit security gate"

            script {
                def high = sh(
                    script: '''
                    docker run --rm \
                      -v "$PWD":/work \
                      alpine:3.19 sh -c "
                        apk add --no-cache jq > /dev/null && \
                        jq '[.results[] | select(.issue_severity == \"HIGH\" or .issue_severity == \"CRITICAL\")] | length' \
                        /work/bandit-report.json
                      "
                    ''',
                    returnStdout: true
                ).trim()

                echo "Bandit HIGH/CRITICAL findings: ${high}"

                if (high.toInteger() > 0) {
                    echo "Bandit security gate triggered"
                    currentBuild.result = 'UNSTABLE'
                }
            }
        }

        stage('Secrets Scan - Gitleaks') {
            echo "Running Gitleaks secrets scan"

            sh '''
            docker run --rm \
              -u $(id -u):$(id -g) \
              -v "$PWD":/repo \
              zricethezav/gitleaks:latest \
              detect \
              --source=/repo \
              --report-format json \
              --report-path /repo/gitleaks-report.json || true
            '''
        }

        stage('Upload Gitleaks to DefectDojo') {
            withCredentials([
                string(credentialsId: 'DEFECTDOJO_API_KEY', variable: 'DD_API_KEY'),
                string(credentialsId: 'DEFECTDOJO_URL',     variable: 'DD_URL')
            ]) {

                sh '''
                echo "Uploading Gitleaks report to DefectDojo..."

                curl -s -X POST "$DD_URL/api/v2/import-scan/" \
                  -H "Authorization: Token $DD_API_KEY" \
                  -F "scan_type=Gitleaks Scan" \
                  -F "product_name=PyGoat" \
                  -F "engagement_name=PyGoat CI/CD" \
                  -F "minimum_severity=Low" \
                  -F "active=true" \
                  -F "verified=false" \
                  -F "close_old_findings=false" \
                  -F "file=@gitleaks-report.json"
                '''
            }
        }

        stage('SCA - Dependency-Track') {
            echo "Generating SBOM and sending to Dependency-Track"

            withCredentials([
                string(credentialsId: 'dependency-track-api-key', variable: 'DT_API_KEY'),
                string(credentialsId: 'dependency-track-url',     variable: 'DT_URL')
            ]) {

                sh '''
                echo "Generating SBOM with Syft (CycloneDX)..."

                docker run --rm \
                  -v "$PWD":/src \
                  anchore/syft:latest \
                  dir:/src -o cyclonedx-xml=/src/bom.xml

                echo "Uploading SBOM to Dependency-Track..."

                curl -s -X POST "$DT_URL/api/v1/bom" \
                  -H "X-Api-Key: $DT_API_KEY" \
                  -F "autoCreate=true" \
                  -F "projectName=PyGoat" \
                  -F "projectVersion=1.0" \
                  -F "bom=@bom.xml"
                '''
            }
        }

        stage('Security Gate - Dependency-Track') {
            echo "Evaluating Dependency-Track security gate"

            withCredentials([
                string(credentialsId: 'dependency-track-api-key', variable: 'DT_API_KEY'),
                string(credentialsId: 'dependency-track-url',     variable: 'DT_URL')
            ]) {

                script {
                    def metrics = sh(
                        script: '''
                        docker run --rm alpine:3.19 sh -c "
                          apk add --no-cache curl jq > /dev/null && \
                          PROJECT_UUID=$(curl -s -H 'X-Api-Key: $DT_API_KEY' \
                            '$DT_URL/api/v1/project?name=PyGoat&version=1.0' \
                            | jq -r '.[0].uuid') && \
                          curl -s -H 'X-Api-Key: $DT_API_KEY' \
                            '$DT_URL/api/v1/metrics/project/'$PROJECT_UUID
                        "
                        ''',
                        returnStdout: true
                    ).trim()

                    def critical = sh(
                        script: """
                        echo '${metrics}' | docker run --rm -i alpine:3.19 sh -c \
                        "apk add --no-cache jq > /dev/null && jq '.critical'"
                        """,
                        returnStdout: true
                    ).trim()

                    def high = sh(
                        script: """
                        echo '${metrics}' | docker run --rm -i alpine:3.19 sh -c \
                        "apk add --no-cache jq > /dev/null && jq '.high'"
                        """,
                        returnStdout: true
                    ).trim()

                    echo "Dependency-Track Critical: ${critical}"
                    echo "Dependency-Track High: ${high}"

                    if (critical.toInteger() > 0 || high.toInteger() > 0) {
                        echo "Dependency-Track security gate triggered"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

    } finally {

        echo "Archiving security artifacts"
        archiveArtifacts artifacts: '*.json,*.xml', fingerprint: true
    }
}
