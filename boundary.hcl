# Disable memory lock: https://www.man7.org/linux/man-pages/man2/mlock.2.html
disable_mlock = true

events {
  observations_enabled = true
  sysevents_enabled = true
  sink "stderr" {
    name = "stderr"
    event_types = [ "*" ]
    # allow_filters = [ "\"/Data/Header/status\" == 404" ]
    # allow_filters = ["\"/data/header/status\" != 200"]
    format = "cloudevents-json"	
  }
  sink {
    name = "file"
    event_types = ["*"]
    format = "cloudevents-text"	
    file {
      path = "./"
      file_name = "err-tmp"
    }
  }
    sink {
    name = "all-events"
    description = "All events sent to file"
    event_types = ["*"]
    format = "cloudevents-json"
    file {
      path = "./"
      file_name = "all-events"
    }
  }
    sink {
    name = "auth-sink"
    description = "Authentications sent to a file"
    event_types = ["observation"]
    format = "cloudevents-json"
    allow_filters = [
      "\"/Data/request_info/Path\" contains \":authenticate\""
    ]
    file {
      path = "/tmp/"
      file_name = "auth-sink"
    }
  }
}


# Controller configuration block
controller {
  # This name attr must be unique across all controller instances if running in HA mode
  name = "demo-controller-1"
  description = "A controller for a demo!"

  # Database URL for postgres. This can be a direct "postgres://"
  # URL, or it can be "file://" to read the contents of a file to
  # supply the url, or "env://" to name an environment variable
  # that contains the URL.
  database {
      url = "postgresql://postgres:postgres@localhost/watchtower?sslmode=disable"
  }

}

worker {
  name = "example-worker"
  description = "An example worker"
}

listener "tcp" {
    purpose = "proxy"
    tls_disable = true
    address = "127.0.0.1"
}

# API listener configuration block
listener "tcp" {
  # Should be the address of the NIC that the controller server will be reached on
  address = "127.0.0.1"
  # The purpose of this listener block
  purpose = "api"

  tls_disable = true

  # Uncomment to enable CORS for the Admin UI. Be sure to set the allowed origin(s)
  # to appropriate values.
  #cors_enabled = true
  #cors_allowed_origins = ["yourcorp.yourdomain.com"]
}

# Data-plane listener configuration block (used for worker coordination)
listener "tcp" {
  # Should be the IP of the NIC that the worker will connect on
  address = "127.0.0.1"
  # The purpose of this listener
  purpose = "cluster"

  tls_disable = true
}

# Root KMS configuration block: this is the root key for Boundary
# Use a production KMS such as AWS KMS in production installs
kms "aead" {
  purpose = "root"
  aead_type = "aes-gcm"
  key = "sP1fnF5Xz85RrXyELHFeZg9Ad2qt4Z4bgNHVGtD6ung="
  key_id = "global_root"
}

# Worker authorization KMS
# Use a production KMS such as AWS KMS for production installs
# This key is the same key used in the worker configuration
kms "aead" {
  purpose = "worker-auth"
  aead_type = "aes-gcm"
  key = "8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GtRBQ="
  key_id = "global_worker-auth"
}

# Recovery KMS block: configures the recovery key for Boundary
# Use a production KMS such as AWS KMS for production installs
kms "aead" {
  purpose = "recovery"
  aead_type = "aes-gcm"
  key = "8fZBjCUfN0TzjEGLQldGY4+iE9AkOvCfjh7+p0GtRBQ="
  key_id = "global_recovery"
}