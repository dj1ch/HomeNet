/**
 * Developer note:
 * In this file, we handle what is too specific to not be in thread_cmd.c.
 * Specifically, instead of handling thread, we use thread to handle specific
 * functions with the chatting.
 * 
 * Most of the stuff here is miscallenous and are more QOL if anything.
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

bool clientDiscovered = false;

/**
 * Get the status of the chat, such as connection
 */
static void get_status(void)
{

}

/**
 * Set the nickname of a discovered client
 */
static void set_nickname(char *nick)
{

}

/**
 * Starts chat with a discovered client
 */
static void start_chat(void) 
{

    // handles client discovery, sets up nickname, etc
    if (clientDiscovered)
    {
        printf("Would you like to set a nickname for the client? (y/n)\n");
        char *ans;

        // to-do: read the console here

        if (ans == 'y') 
        {
            printf("Nickname: \n");

            // to-do: read the console here as well

            char *nick;

            printf("Set nickname: '%s'\n", nick);
            ans = ' ';
            
            printf("Is this okay?\n");

            // to-do: read the console here as well

            if (ans == 'y')
            {
                set_nickname(nick);
            }
        }
    }
}

static void register_chat(void)
{
    
}

