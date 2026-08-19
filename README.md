# Venandi

Venandi is a backend server software for scavenger hunt events. The software manages user accounts, event levels, and flag submissions.

## Components

The server uses these technologies:
* Rust programming language
* Axum web framework
* Tokio asynchronous runtime
* SQLite database with SQLx
* Serenity for Discord integration

## Functions

The Venandi server performs these functions:
* Manages user registration and authentication.
* Processes flag submissions from users.
* Calculates scores for users.
* Validates level structures.
* Sends event notifications to a Discord channel.
* Provides real-time updates through WebSockets.

## Configuration

You must configure the server before you start it. 

1. Copy the `.env.example` file to a new file named `.env`.
2. Add the correct values to the `.env` file. 
3. Edit the `config/hunt.json` file to define the event levels.

## Operation

To compile the software, execute this command:
```bash
cargo build --release
```

To start the server, execute this command:
```bash
cargo run --release
```
