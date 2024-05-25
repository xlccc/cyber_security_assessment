#include"Command_Excute.h"
std::string execute_commands(ssh_session session, string commands)
{   
    ssh_channel channel = ssh_channel_new(session);
    if (channel == NULL)
    {
        std::cerr << "Error creating SSH channel: " << ssh_get_error(session) << std::endl;
        return ""; // 返回空字符串
    }

    int rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
        std::cerr << "Error opening SSH channel: " << ssh_get_error(session) << std::endl;
        ssh_channel_free(channel);
        return ""; // 返回空字符串
    }

    rc = ssh_channel_request_exec(channel, commands.c_str());
    if (rc != SSH_OK)
    {
        std::cerr << "Error executing remote command: " << ssh_get_error(session) << std::endl;
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return ""; // 返回空字符串
    }

    std::stringstream output;
    char buffer[256];
    int nbytes;
    while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0)) > 0)
    {
        output.write(buffer, nbytes);
    }

    if (nbytes < 0)
    {
        std::cerr << "Error reading SSH channel: " << ssh_get_error(session) << std::endl;
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }

    

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    

    return output.str();
}
