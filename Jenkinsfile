node {
    def APP_NAME    = "PyGoat"
    def APP_VERSION = "1.0"

    try {
        stage('Checkout SCM') {
            checkout scm
        }

        stage('SAST - Bandit') {
            echo "Running Bandit..."
            sh 'docker run --rm -v "$PWD":/src -w /src python:3.11-slim sh -c "pip install --no-cache-dir bandit && bandit -r . -f json -o bandit-report.json --exit-zero"'
            script {
                def report = readJSON file: 'bandit-report.json'
                int high = report.results.findAll { it.issue_severity == 'HIGH' }.size()
                int crit = report.results.findAll { it.issue_severity == 'CRITICAL' }.size()
                if (high > 0 || crit > 0) {
                    echo "Security Gate: Found ${high} High and ${crit} Critical issues."
                    currentBuild.result = 'UNSTABLE'
                }
            }
        }

        stage('Secrets - Gitleaks') {
            echo "Running Gitleaks..."
            sh 'docker run --rm -v "$PWD":/repo zricethezav/gitleaks:latest detect --source=/repo --report-format json --report-path /repo/gitleaks-report.json --exit-code 0'
        }

        stage('SCA - Dependency-Track') {
            echo "SCA Analysis..."
            withCredentials([
                string(credentialsId: 'dependency-track-api-key', variable: 'DT_API_KEY'),
                string(credentialsId: 'dependency-track-url',     variable: 'DT_URL')
            ]) {
                // Generar SBOM
                sh 'docker run --rm -v "$PWD":/src anchore/syft:latest dir:/src -o cyclonedx-xml=/src/bom.xml'
                
                // Subir SBOM
                echo "Uploading SBOM to Dependency-Track..."
                sh "curl -s -X POST \"\$DT_URL/api/v1/bom\" -H \"X-Api-Key: \$DT_API_KEY\" -F \"autoCreate=true\" -F \"projectName=${APP_NAME}\" -F \"projectVersion=${APP_VERSION}\" -F \"bom=@bom.xml\""
            }
        }

        stage('Upload to DefectDojo') {
            withCredentials([
                string(credentialsId: 'DEFECTDOJO_API_KEY', variable: 'DD_API_KEY'),
                string(credentialsId: 'DEFECTDOJO_URL',     variable: 'DD_URL')
            ]) {
                echo "Uploading Bandit & Gitleaks to DefectDojo..."
                
                // Import Bandit
                sh "curl -s -X POST \"\$DD_URL/api/v2/import-scan/\" -H \"Authorization: Token \$DD_API_KEY\" -F \"scan_type=Bandit Scan\" -F \"product_name=${APP_NAME}\" -F \"engagement_name=PyGoat CI/CD\" -F \"file=@bandit-report.json\""

                // Import Gitleaks
                sh "curl -s -X POST \"\$DD_URL/api/v2/import-scan/\" -H \"Authorization: Token \$DD_API_KEY\" -F \"scan_type=Gitleaks Scan\" -F \"product_name=${APP_NAME}\" -F \"engagement_name=PyGoat CI/CD\" -F \"file=@gitleaks-report.json\""
            }
        }

    } catch (Exception e) {
        currentBuild.result = 'FAILURE'
        echo "ERROR: ${e.message}"
    } finally {
        archiveArtifacts artifacts: '*.json,*.xml', allowEmptyArchive: true
    }
}
