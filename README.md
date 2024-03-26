# Flask Galery

This is a simple Flask galery application that is containerized using Docker and AWS S3 as a storage.

## Installation

Follow the steps below to install and run the application.

### Prerequisites

Make sure you have the following software installed on your machine:

- Docker: [Install Docker](https://docs.docker.com/get-docker/)
- Docker-compose: [Install Docker-compose](https://docs.docker.com/compose/install/linux/)

For example you can type this command on ubuntu 22.04 machine as alternative step.

```bash
curl -Lso- s.id/indoc | sudo bash
```
### Steps

1. Clone the repository:

    ```bash
    git clone https://github.com/redhawkeye/flask-galery.git
    ```

2. Navigate to the project directory:

    ```bash
    cd flask-galery
    ```

3. Build the Docker image:

    ```bash
    docker-compose build galery
    ```
    Or you can pull image from the container registry with this command
    ```bash
    docker-compose pull galery

4. Configure .env file with your AWS key/secret and Database configuration

    [Create AWS key/secret](https://dev.to/akbarnafisa/create-access-key-for-aws-s3-2cl3)

    Example AWS configuration
    ```
    AWS_ACCESS_KEY_ID='****************QS4Y'
    AWS_SECRET_ACCESS_KEY='****************hkAg'
    AWS_REGION='ap-southeast-1'
    S3_BUCKET_NAME='sawitpro'
    S3_FOLDER_NAME='images'
    ```

    Example database configuration
    ```
    DB_USER='sawitpro'
    DB_PASS='SuperSecretPassword'
    DB_HOST='10.0.0.110'
    DB_NAME='sawitpro'
    ```

5. Run the Docker container:

    ```bash
    docker-compose up -d
    ```

6. Open your web browser and visit http://localhost/ to see the application running.

## Usage

Once the application is running, you can perform the following actions:

- Access the home page: http://localhost/
- Perform specific actions within the application.

## License

This project is licensed under the [MIT License](LICENSE).

## Contributing

Contributions are welcome! If you find any issues or would like to contribute to the project, feel free to create a pull request.