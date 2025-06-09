from celery import Celery

# This file configures the Celery application instance for KAIROS Core.
# Celery is used for running background tasks, such as more detailed scans,
# without blocking the main application's web server.

# Environment variables for broker and backend URLs are typically set in docker-compose.yml
# and passed to the Celery application here.
# Example for RabbitMQ broker and Redis backend:
# CELERY_BROKER_URL=amqp://guest:guest@rabbitmq:5672//
# CELERY_RESULT_BACKEND=redis://redis:6379/0

# Initialize the Celery application.
# "kairos_tasks" is the name of the Celery application.
celery_app = Celery(
    "kairos_tasks",
    broker="amqp://guest:guest@rabbitmq:5672//",  # URL for the message broker (RabbitMQ)
                                                 # Assumes 'rabbitmq' is the service name in Docker network.
    backend="redis://redis:6379/0",              # URL for the result backend (Redis)
                                                 # Assumes 'redis' is the service name in Docker network.
                                                 # The '/0' specifies Redis database number 0.
    include=["app.tasks"]                        # List of modules to import when a worker starts.
                                                 # This is where task definitions (e.g., in tasks.py) are located.
)

# Update Celery configuration with additional settings.
celery_app.conf.update(
    task_serializer="json",        # Specifies the default serialization method for task messages (JSON).
    accept_content=["json"],       # List of content types/serializers to accept.
    result_serializer="json",      # Specifies the serialization method for task results (JSON).
    timezone="UTC",                # Sets the timezone for Celery to UTC.
    enable_utc=True,               # Ensures Celery uses UTC.
    broker_connection_retry_on_startup=True, # Automatically retry broker connection on Celery worker startup.
)

# This block allows running the Celery worker directly using `python -m app.celery_app worker ...`
# (though typically workers are started via the `celery` CLI command specified in docker-compose.yml).
if __name__ == "__main__":
    celery_app.start()
