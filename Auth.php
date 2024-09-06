<?php
/**
 * A Simple PHP Login System by Unconventional Coding
 */
class Auth
{
    public function __construct(
        protected PDO $db,
    ) {}

    /**
     * Adds a user into the database
     *
     * @param string $username The username
     * @param string $password The password
     * @param int $role The user role
     *
     * @return int|false Returns the ID of the added user or false on failure
     */
    public function add_user(
        string $username,
        string $password,
        int $role,
    ): int|false {
        $username = trim( $username );
        $password = trim( $password );

        $hash = password_hash( $password, PASSWORD_DEFAULT );

        if( $hash === false ) {
            return false;
        }

        if( $hash === null ) {
            throw new \Exception( "Invalid hashing algorithm!" );
        }

        // TODO: Check if user already exists

        try {
            $stmt = $this->db->prepare( "INSERT INTO users (username, password, role) VALUES (:username, :password, :role)" );
            $stmt->execute( [
                ":username" => $username,
                ":password" => $hash,
                ":role" => $role,
            ] );
        } catch( \PDOException $e ) {
            error_log( $e->getMessage() );
            return false;
        }

        $id = $this->db->lastInsertId();

        if( $id === false ) {
            return false;
        }

        return intval( $id );
    }

    /**
     * Authenticate a user with a username and password
     *
     * @param string $username The username
     * @param string $password The password
     *
     * @return int|false The ID of the username matching the
     *                   username/password or false if user
     *                   not found
     */
    public function authenticate(
        string $username,
        string $password,
    ): int|false {
        $username = trim( $username );
        $password = trim( $password );

        try {
            $stmt = $this->db->prepare( "SELECT id, password FROM users WHERE username = :username" );
            $stmt->execute( [
                ":username" => $username,
            ] );
        } catch( \PDOException $e ) {
            error_log( $e->getMessage() );
            return false;
        }

        $user = $stmt->fetch( PDO::FETCH_ASSOC );

        if( $user === false ) {
            return false;
        }

        if( ! isset( $user["password"] ) ) {
            throw new \Exception( "Password column not found in database!" );
        }

        if( ! isset( $user["id"] ) ) {
            throw new \Exception( "ID column not found in database!" );
        }

        $verify = password_verify( $password, $user["password"] );

        if( $verify === true ) {
            return intval( $user["id"] );
        }

        return false;
    }

    /**
     * Gets the role of the user from the database
     *
     * @param int $user_id The ID of the user whose role to get
     *
     * @return int|false Returns the role ID or false on failure
     */
    public function get_user_role( int $user_id ): int|false {
        try {
            $stmt = $this->db->prepare( "SELECT role FROM users WHERE id = :user_id" );
            $stmt->execute( [
                ":user_id" => $user_id,
            ] );
        } catch( \PDOException $e ) {
            error_log( $e->getMessage() );
            return false;
        }

        $role = $stmt->fetchColumn();

        if( $role === false ) {
            return false;
        }

        return intval( $role );
    }

    /**
     * Logs a user into the session and regenerates session ID
     *
     * @return void
     */
    public function log_user_in( int $user_id ): void {
        if( session_status() === PHP_SESSION_NONE ) {
            throw new \Exception( "Session has not been started!" );
        }

        session_regenerate_id( true );

        $_SESSION["logged_in_user"] = $user_id;
    }

    /**
     * Logs a user out of the session and regenerates session ID
     *
     * @return void
     */
    public function log_user_out(): void {
        if( session_status() === PHP_SESSION_NONE ) {
            throw new \Exception( "Session has not been started!" );
        }

        session_regenerate_id( true );

        $_SESSION["logged_in_user"] = null;
    }

    /**
     * Gets which user is logged in
     *
     * @return int|false Returns the ID of the logged in user
     *                   or false if nobody is logged in
     */
    public function logged_in_user(): int|false {
        if( session_status() === PHP_SESSION_NONE ) {
            throw new \Exception( "Session has not been started!" );
        }

        if( ! isset( $_SESSION["logged_in_user"] ) ) {
            return false;
        }

        if( ! $_SESSION["logged_in_user"] ) {
            return false;
        }

        return intval( $_SESSION["logged_in_user"] );
    }
}
