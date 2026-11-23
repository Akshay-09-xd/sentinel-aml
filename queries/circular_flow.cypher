// A closed path with unique intermediate accounts and chronological transfers.
// $ids scopes detection to the current workspace's imported transfers.
MATCH p=(a:SentinelAccount)-[:SENTINEL_TRANSFER*2..5]->(a)
WITH p, relationships(p) AS rels, nodes(p)[0..-1] AS accounts
WHERE all(n IN accounts WHERE single(m IN accounts WHERE m = n))
  AND all(r IN rels WHERE r.id IN $ids AND r.amount_minor >= 100000)
  AND all(i IN range(0, size(rels)-2)
    WHERE datetime(rels[i].timestamp) < datetime(rels[i+1].timestamp))
  AND datetime(last(rels).timestamp) <= datetime(head(rels).timestamp) + duration('PT24H')
  AND all(r IN rels WHERE r.amount_minor * 5 >= 4 *
    reduce(largest = 0, x IN rels |
      CASE WHEN x.amount_minor > largest THEN x.amount_minor ELSE largest END))
RETURN [r IN rels | r.id] AS transfer_ids, [r IN rels | r.timestamp] AS path_times
ORDER BY path_times, transfer_ids
LIMIT 10001
