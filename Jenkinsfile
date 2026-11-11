pipeline {
  agent any
  tools { nodejs 'Node-24' }
  options { timestamps(); disableConcurrentBuilds() }
  stages {
    stage('Install') { steps { sh 'npm ci' } }
    stage('Type check') { steps { sh 'npm run check -w server' } }
    stage('Lint') { steps { sh 'npm run lint' } }
    stage('Tests') { steps { sh 'npm test' } }
    stage('Production build') { steps { sh 'npm run build' } }
  }
  post { always { archiveArtifacts artifacts: 'client/dist/**,server/dist/**', allowEmptyArchive: true } }
}
