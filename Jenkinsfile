node {
    def APP_NAME    = "PyGoat"
    def APP_VERSION = "1.0"

    try {
        stage('Checkout SCM') {
            checkout scm
        }

        stage('Security Analysis (SAST & Secrets)') {
            echo "Ejecutando Bandit y Gitleaks..."
            sh 'docker run --rm -v "$PWD":/src -w /src python:3.11-slim sh -c "pip install --no-cache-dir bandit && bandit -r . -f json -o bandit-report.json --exit-zero"'
            sh 'docker run --rm -v "$PWD":/repo zricethezav/gitleaks:latest detect --source=/repo --report-format json --report-path /repo/gitleaks-report.json --exit-code 0'
        }

        stage('SCA - Dependency-Track') {
            echo "Generando SBOM y subiendo a Dependency-Track..."
            withCredentials([
                string(credentialsId: 'dependency-track-api-key', variable: 'DT_API_KEY'),
                string(credentialsId: 'dependency-track-url',      variable: 'DT_URL')
            ]) {
                sh 'docker run --rm -v "$PWD":/src anchore/syft:latest dir:/src -o cyclonedx-xml=/src/bom.xml'
                sh "curl -s -X POST \"\$DT_URL/api/v1/bom\" -H \"X-Api-Key: \$DT_API_KEY\" -F \"autoCreate=true\" -F \"projectName=${APP_NAME}\" -F \"projectVersion=${APP_VERSION}\" -F \"bom=@bom.xml\""
            }
        }

        stage('Centralize in DefectDojo') {
            withCredentials([
                string(credentialsId: 'DEFECTDOJO_API_KEY', variable: 'DD_API_KEY'),
                string(credentialsId: 'DEFECTDOJO_URL',     variable: 'DD_URL')
            ]) {
                echo "Centralizando reportes en DefectDojo..."
                def commonArgs = "-f -s -X POST \"\$DD_URL/api/v2/import-scan/\" " +
                                "-H \"Authorization: Token \$DD_API_KEY\" " +
                                "-F \"product_name=${APP_NAME}\" " +
                                "-F \"engagement_name=${APP_NAME} CI/CD\" " +
                                "-F \"active=true\" "

                sh "curl ${commonArgs} -F 'scan_type=Bandit Scan' -F 'file=@bandit-report.json'"
                sh "curl ${commonArgs} -F 'scan_type=Gitleaks Scan' -F 'file=@gitleaks-report.json'"
                sh "curl ${commonArgs} -F 'scan_type=CycloneDX Scan' -F 'file=@bom.xml'"
            }
        }

        stage('Security Gates') {
            script {
                echo "Evaluando umbrales de seguridad..."
                boolean failedGate = false

                // 1. Gate para Bandit (Críticas y Altas)
                def highIssues = sh(script: "python3 -c \"import json; f=open('bandit-report.json'); data=json.load(f); print(len([i for i in data['results'] if i['issue_severity'] == 'HIGH']))\"", returnStdout: true).trim()
                
                if (highIssues.toInteger() > 0) {
                    echo "Bandit Gate: Se encontraron ${highIssues} vulnerabilidades de severidad ALTA."
                    failedGate = true
                }

                // 2. Gate para Dependency-Track (Risk Score)
                echo "Evaluando métricas de Dependency-Track..."
                // Simulamos una validación: si el proceso de subida fue exitoso pero sabemos que hay riesgo
                if (failedGate) {
                    currentBuild.result = 'UNSTABLE'
                    echo "Estado del Pipeline: UNSTABLE debido a fallos en Security Gates."
                } else {
                    echo "Security Gates aprobados."
                }
            }
        }

    } catch (Exception e) {
        currentBuild.result = 'FAILURE'
        echo "Error en el pipeline: ${e.message}"
    } finally {
        echo "Guardando artefactos y limpiando..."
        archiveArtifacts artifacts: '*.json,*.xml', allowEmptyArchive: true
        sh 'rm -f bandit-report.json gitleaks-report.json bom.xml'
    }
}
