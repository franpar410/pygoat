pipeline {
    agent any
    stages {
        stage('SAST-Semgrep') {
            agent {
                docker {
                    image 'python:3.11-slim' //utilizamos la imagen que contine python y pip instalados
                    args '-u root' //para ejecutar los comandos como root y evitar problemas de permisos (esto es una mala práctica y lo ideal sería crear una imagen con las herramientas necesarias ya instaladas)
                }
            }
            steps {
                script{
                    sh 'apt-get update && apt-get install -qq -y git'
                    sh 'git config --global --add safe.directory $(pwd)'
                    sh 'pip install -q semgrep'
                    try {
                        sh 'semgrep scan --json-output=semgrep.json --error .' // con el flag --json-output generamos un reporte en formato json y con --error hacemos que semgrep devuelva un código de salida distinto de 0 si encuentra alguna vulnerabilidad
                    }
                    catch (err) {                                        
                        unstable(message: "Findings found") // marcamos el build como inestable si semgrep encuentra vulnerabilidades o si queremos bloquearlo podemos usar "error" en lugar de "unstable"
                    }
                }
            }
        }        
        stage('Compilation') {
            agent {
                docker { image 'php:8.2-cli' }
            }
            steps {
                sh 'echo "Compilando..."'
            }
        }
        stage('Build') {
            agent {
                docker { image 'php:8.2-cli' }
            }
            steps {
                sh 'echo "docker build -t my-php-app ."'
            }
        }
        stage('Deploy') {
            agent {
                docker { image 'php:8.2-cli' }
            }
            steps {
                sh 'echo "docker run my-php-app ."'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'semgrep.json', fingerprint: true // guardamos el reporte de semgrep como artefacto del build para que persista en Jenkins
        }
    }
}
