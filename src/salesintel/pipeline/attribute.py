"""Attribution: each feature row -> account (registrable domain), direct or via-IP (D23, D24).

- direct: the record names the domain itself; the record's account is its first (highest
  priority) candidate name.
- via-IP: the record names nothing, its IP has exactly one candidate domain (using the full-file
  count carried into a sample, D43), and the IP's org is neither CDN nor cloud / hosting.
- unresolved: everything else (counted in the funnel, never attributed).
CDN edge records keep their direct attribution but only ever produce the "behind CDN" fact.
"""

from pathlib import Path

import duckdb


def attribute(con: duckdb.DuckDBPyConnection, features: Path) -> None:
    """Create view `attributed` (all feature columns + domain, attribution, source).

    `feat` and `attributed` are views streamed from Parquet; only the per-IP index is a table.
    Materializing them held the whole 8.5M-row feature layer in memory twice (13.5 GB peak on the
    full file, DATA_NOTES 5c).
    """
    con.execute(f"CREATE OR REPLACE VIEW feat AS SELECT * FROM read_parquet('{features}/part-*.parquet')")
    con.execute(
        """
        CREATE OR REPLACE TABLE ip_domains AS
        WITH pairs AS (
            SELECT DISTINCT ip, n.domain AS domain FROM feat, unnest(names) AS t(n)
        ), local AS (
            SELECT ip, count(*) AS local_n, min(domain) AS only_domain FROM pairs GROUP BY ip
        ), carried AS (
            SELECT ip, max(sample_ip_domain_count) AS carried_n,
                   bool_or(infra_class IS NOT NULL) AS infra_ip  -- any record on the IP is CDN / cloud (D63)
            FROM feat GROUP BY ip
        )
        SELECT l.ip, l.only_domain, greatest(l.local_n, coalesce(c.carried_n, 0)) AS ip_domain_count,
               coalesce(c.infra_ip, false) AS infra_ip
        FROM local l LEFT JOIN carried c USING (ip)
        """
    )
    con.execute(
        """
        CREATE OR REPLACE VIEW attributed AS
        SELECT f.*,
            CASE
                WHEN len(f.names) > 0 THEN f.names[1].domain
                WHEN f.infra_class IS NULL AND NOT d.infra_ip AND d.ip_domain_count = 1 THEN d.only_domain
            END AS domain,
            CASE
                WHEN len(f.names) > 0 THEN 'direct'
                WHEN f.infra_class IS NULL AND NOT d.infra_ip AND d.ip_domain_count = 1 THEN 'via_ip'
                ELSE 'unresolved'
            END AS attribution,
            CASE WHEN len(f.names) > 0 THEN f.names[1].source END AS source,
            coalesce(d.ip_domain_count, 0) AS ip_domain_count
        FROM feat f LEFT JOIN ip_domains d USING (ip)
        """
    )


def funnel(con: duckdb.DuckDBPyConnection) -> list[tuple]:
    return con.execute(
        """
        SELECT attribution, coalesce(infra_class, 'customer_or_isp') AS class, count(*) AS records,
               count(DISTINCT domain) AS domains
        FROM attributed GROUP BY ALL ORDER BY attribution, class
        """
    ).fetchall()
