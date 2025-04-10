CREATE TABLE user (id integer NOT NULL, username character varying(64) NOT NULL, email character varying(120) NOT NULL, password_hash character varying(256) NOT NULL, first_name character varying(64), last_name character varying(64), is_active boolean, is_email_confirmed boolean, created_at timestamp without time zone, last_login timestamp without time zone, last_ip character varying(45), last_user_agent character varying(256), two_factor_enabled boolean, department character varying(64));

CREATE TABLE user_roles (user_id integer, role_id integer);

CREATE TABLE role (id integer NOT NULL, name character varying(64) NOT NULL, description character varying(256));

CREATE TABLE notification (id integer NOT NULL, user_id integer NOT NULL, title character varying(128) NOT NULL, message text NOT NULL, is_read boolean, is_dismissed boolean, created_at timestamp without time zone);

CREATE TABLE password_reset_token (id integer NOT NULL, user_id integer NOT NULL, token character varying(64) NOT NULL, created_at timestamp without time zone, expires_at timestamp without time zone NOT NULL, is_used boolean);

CREATE TABLE two_factor_token (id integer NOT NULL, user_id integer NOT NULL, token character varying(6) NOT NULL, created_at timestamp without time zone, expires_at timestamp without time zone NOT NULL, is_used boolean);

CREATE TABLE session_activity (id integer NOT NULL, user_id integer NOT NULL, session_id character varying(128) NOT NULL, ip_address character varying(45) NOT NULL, user_agent character varying(256) NOT NULL, created_at timestamp without time zone, last_activity timestamp without time zone, is_active boolean);

CREATE TABLE task (id integer NOT NULL, user_id integer NOT NULL, title character varying(128) NOT NULL, description text, due_date date, priority character varying(20), category character varying(50), is_completed boolean, created_at timestamp without time zone, updated_at timestamp without time zone, completed_at timestamp without time zone);

CREATE TABLE ticket (id integer NOT NULL, title character varying(128) NOT NULL, description text NOT NULL, status character varying(20), priority character varying(20), creator_id integer NOT NULL, assignee_id integer, due_date date, category character varying(50), created_at timestamp without time zone, updated_at timestamp without time zone, resolved_at timestamp without time zone, client_id integer);

CREATE TABLE client (id integer NOT NULL, name character varying(100) NOT NULL, email character varying(120) NOT NULL, phone character varying(20), company character varying(100), address character varying(200), city character varying(50), state character varying(50), zip_code character varying(20), country character varying(50), is_active boolean, notes text, created_at timestamp without time zone, updated_at timestamp without time zone);

CREATE TABLE ticket_comment (id integer NOT NULL, ticket_id integer NOT NULL, user_id integer NOT NULL, content text NOT NULL, created_at timestamp without time zone, updated_at timestamp without time zone);

CREATE TABLE login_attempt (id integer NOT NULL, user_id integer NOT NULL, ip_address character varying(45), user_agent character varying(256), timestamp timestamp without time zone, successful boolean);

