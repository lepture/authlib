@Library('shared-library') _
import quarticpipeline.PipelineBuilder

containerNodes = [
  Test: [
    dir: './jenkins-scripts/',
    steps: [
      test: [
        file_name: 'test.sh',
        docker_image: 'python:3.6',
        docker_image_args: '-u root'
      ]
    ]
  ],
  Publish: [
    dir: './jenkins-scripts/',
    steps: [
      publish: [
        file_name: 'publish.sh',
        docker_image: 'python:3.6',
        docker_image_args: '-u root'
      ]
    ]
  ]
]

pipelineBuilder = new PipelineBuilder(this, env, scm, containerNodes)
userEnv = ['RESERVE=azubuntu']

pipelineBuilder.executePipeline(userEnv)
