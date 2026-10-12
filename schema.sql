DROP TABLE IF EXISTS abc_posts;
DROP TABLE IF EXISTS abc_users;
-- Drop likes and views too if you have

CREATE TABLE abc_users (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    username VARCHAR(150) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user'
);

CREATE TABLE abc_posts (
    id SERIAL PRIMARY KEY,
    title TEXT,
    content TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    user_id UUID REFERENCES users(id)
);



CREATE OR REPLACE FUNCTION handle_new_abc_user()
RETURNS trigger AS $$
BEGIN
  INSERT INTO public.abc_users (id, username)
  VALUES (NEW.id, split_part(NEW.email, '@', 1));
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;



CREATE TRIGGER on_auth_abc_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE PROCEDURE handle_new_abc_user();



INSERT INTO public.abc_users (id, username)
SELECT id, split_part(email, '@', 1) FROM auth.users
ON CONFLICT (id) DO NOTHING;
