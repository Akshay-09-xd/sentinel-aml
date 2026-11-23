// Every incoming transfer is a candidate end for a rolling 24-hour window.
MATCH ()-[end:SENTINEL_TRANSFER]->(target:SentinelAccount)
WHERE end.id IN $ids
WITH DISTINCT target, end.timestamp AS window_end
MATCH (source:SentinelAccount)-[r:SENTINEL_TRANSFER]->(target)
WHERE r.id IN $ids
  AND datetime(r.timestamp) >= datetime(window_end) - duration('PT24H')
  AND datetime(r.timestamp) <= datetime(window_end)
WITH target, window_end, collect(r.id) AS transfer_ids,
     count(DISTINCT source) AS senders, sum(r.amount_minor) AS volume
WHERE senders >= 4 AND volume >= 2000000
RETURN target.id AS target_id, transfer_ids, senders, volume, window_end
ORDER BY target_id, senders DESC, volume DESC, window_end
LIMIT 1001
