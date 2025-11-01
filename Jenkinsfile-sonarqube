pipeline {
    agent any
    stages {
        stage('SonarQube analysis') {
            steps {
                script {
                    scannerHome = tool 'sonarqube-scanner'// debe coincidir con el nombre de definido en Jenkins -> Manage Jenkins -> Tool Configuration
                }
                withSonarQubeEnv('Sonarqube-docker') {// Si ha configurado más de una conexión de servidor global, puede especificar su nombre según lo configurado en Jenkins
                    sh "${scannerHome}/bin/sonar-scanner -Dsonar.projectKey=jenkins-testing -Dsonar.sources=."                }
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
}
