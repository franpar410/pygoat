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
              sh -c "pip install --no-cache-dir bandit && bandit -r . -f json -o bandit-report.json --exit-zero"
            '''
        }

        stage('Upload Bandit to DefectDojo') {
            withCredentials([
                string(credentialsId: 'DEFECTDOJO_API_KEY', variable: 'DD_API_KEY'),
                string(credentialsId: 'DEFECTDOJO_URL',     variable: 'DD_URL')
            ]) {
                sh '''
                echo "Uploading Bandit report to DefectDojo..."
                # Nota: Se eliminó el / final de la variable para evitar //api
                curl -s -X POST "${DD_URL}/api/v2/import-scan/" \
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
                // Se simplificó el escape de comillas para JQ
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
                    echo "Bandit security gate triggered: Found ${high} vulnerabilities"
                    currentBuild.result = 'UNSTABLE'
                }
            }
        }
        
        // ... resto de las etapas (Gitleaks, Dependency-Track) ...

    } catch (Exception e) {
        currentBuild.result = 'FAILURE'
        echo "Error: ${e.getMessage()}"
    } finally {
        echo "Archiving security artifacts"
        archiveArtifacts artifacts: '*.json,*.xml', fingerprint: true, allowEmptyArchive: true
    }
}
