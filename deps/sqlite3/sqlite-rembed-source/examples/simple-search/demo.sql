.bail on
.mode table
.header on

.timer on

.load ../../dist/debug/rembed0
.load ../../../sqlite-vec/dist/vec0

INSERT INTO temp.rembed_clients(name, options)
 VALUES ('text-embedding-3-small', 'openai');

create table articles(headline text);


-- Random NPR headlines from 2024-06-04
insert into articles VALUES
  ('Shohei Ohtani''s ex-interpreter pleads guilty to charges related to gambling and theft'),
  ('The jury has been selected in Hunter Biden''s gun trial'),
  ('Larry Allen, a Super Bowl champion and famed Dallas Cowboy, has died at age 52'),
  ('After saying Charlotte, a lone stingray, was pregnant, aquarium now says she''s sick'),
  ('An Epoch Times executive is facing money laundering charge');


-- Seed a vector table with embeddings of article headlines, using OpenAI's API
create virtual table vec_articles using vec0(headline_embeddings float[1536]);

insert into vec_articles(rowid, headline_embeddings)
  select rowid, rembed('text-embedding-3-small', headline)
  from articles;


.param set :query 'firearm courtroom'

with matches as (
  select
    rowid,
    distance
  from vec_articles
  where headline_embeddings match rembed('text-embedding-3-small', :query)
  order by distance
  limit 3
)
select
  headline,
  distance
from matches
left join articles on articles.rowid = matches.rowid;
