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
              sh -c "pip install --no-cache-dir bandit && \
                     bandit -r . -f json -o bandit-report.json --exit-zero"
            '''
        }

        stage('Upload Bandit to DefectDojo') {
            withCredentials([
                string(credentialsId: 'DEFECTDOJO_API_KEY', variable: 'DD_API_KEY'),
                string(credentialsId: 'DEFECTDOJO_URL',     variable: 'DD_URL')
            ]) {
                sh '''
                echo "Uploading Bandit report to DefectDojo..."
                curl -s -X POST "${DD_URL}/api/v2/import-scan/" \
                  -H "Authorization: Token $DD_API_KEY" \
                  -F "scan_type=Bandit Scan" \
                  -F "product_name=${APP_NAME}" \
                  -F "engagement_name=${APP_NAME} CI/CD" \
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
                // Corrección de comillas para JQ
                def high = sh(
                    script: """
                    docker run --rm -v "\$PWD":/work alpine:3.19 sh -c '
                        apk add --no-cache jq > /dev/null && \
                        jq "[.results[] | select(.issue_severity == \\"HIGH\\" or .issue_severity == \\"CRITICAL\\")] | length" /work/bandit-report.json
                    '
                    """,
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
            // Se usa --exit-code 0 para que no falle el step si encuentra secretos, permitiendo que el pipeline siga a DefectDojo
            sh '''
            docker run --rm \
              -v "$PWD":/repo \
              zricethezav/gitleaks:latest \
              detect \
              --source=/repo \
              --report-format json \
              --report-path /repo/gitleaks-report.json \
              --exit-code 0
            '''
        }

        stage('Upload Gitleaks to DefectDojo') {
            withCredentials([
                string(credentialsId: 'DEFECTDOJO_API_KEY', variable: 'DD_API_KEY'),
                string(credentialsId: 'DEFECTDOJO_URL',     variable: 'DD_URL')
            ]) {
                sh '''
                echo "Uploading Gitleaks report to DefectDojo..."
                curl -s -X POST "${DD_URL}/api/v2/import-scan/" \
                  -H "Authorization: Token $DD_API_KEY" \
                  -F "scan_type=Gitleaks Scan" \
                  -F "product_name=${APP_NAME}" \
                  -F "engagement_name=${APP_NAME} CI/CD" \
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
                docker run --rm -v "$PWD":/src anchore/syft:latest \
                  dir:/src -o cyclonedx-xml=/src/bom.xml

                echo "Uploading SBOM to Dependency-Track..."
                curl -s -X POST "${DT_URL}/api/v1/bom" \
                  -H "X-Api-Key: $DT_API_KEY" \
                  -F "autoCreate=true" \
                  -F "projectName=${APP_NAME}" \
                  -F "projectVersion=${APP_VERSION}" \
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
                    // Obtener métricas y procesar con JQ en un solo bloque para evitar errores de eco
                    def critical = sh(
                        script: """
                        docker run --rm alpine:3.19 sh -c '
                            apk add --no-cache curl jq > /dev/null && \
                            UUID=\$(curl -s -H "X-Api-Key: $DT_API_KEY" "$DT_URL/api/v1/project?name=$APP_NAME&version=$APP_VERSION" | jq -r ".[0].uuid") && \
                            curl -s -H "X-Api-Key: $DT_API_KEY" "$DT_URL/api/v1/metrics/project/\$UUID" | jq ".critical"
                        '
                        """,
                        returnStdout: true
                    ).trim()

                    def high = sh(
                        script: """
                        docker run --rm alpine:3.19 sh -c '
                            apk add --no-cache curl jq > /dev/null && \
                            UUID=\$(curl -s -H "X-Api-Key: $DT_API_KEY" "$DT_URL/api/v1/project?name=$APP_NAME&version=$APP_VERSION" | jq -r ".[0].uuid") && \
                            curl -s -H "X-Api-Key: $DT_API_KEY" "$DT_URL/api/v1/metrics/project/\$UUID" | jq ".high"
                        '
                        """,
                        returnStdout: true
                    ).trim()

                    echo "Dependency-Track Critical: ${critical} | High: ${high}"

                    if (critical.toInteger() > 0 || high.toInteger() > 0) {
                        echo "Dependency-Track security gate triggered"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

    } catch (Exception e) {
        currentBuild.result = 'FAILURE'
        echo "Pipeline failed due to: ${e.message}"
    } finally {
        echo "Archiving security artifacts"
        archiveArtifacts artifacts: '*.json,*.xml', fingerprint: true, allowEmptyArchive: true
    }
}
