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

    } finally {

        echo "Archiving security artifacts"
        archiveArtifacts artifacts: '*.json,*.xml', fingerprint: true
    }
}
