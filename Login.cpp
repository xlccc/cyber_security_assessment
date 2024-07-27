#include"Login.h"
ssh_session initialize_ssh_session(const char* hostname, const char* username, const char* password)
{
    ssh_session session = ssh_new();
    if (session == NULL)
    {
        std::cerr << "Failed to create SSH session." << std::endl;
        return NULL;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, hostname);
    ssh_options_set(session, SSH_OPTIONS_USER, username);

    int rc = ssh_connect(session);
    if (rc != SSH_OK)
    {
        std::cerr << "Error connecting to remote host: " << ssh_get_error(session) << std::endl;
        ssh_free(session);
        return NULL;
    }

    rc = ssh_userauth_password(session, NULL, password);
    if (rc != SSH_AUTH_SUCCESS)
    {
        std::cerr << "Authentication failed: " << ssh_get_error(session) << std::endl;
        ssh_disconnect(session);
        ssh_free(session);
        return NULL;
    }

    return session;
}

