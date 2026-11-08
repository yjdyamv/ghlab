"""Campaign clustering maths: pure functions over plain profiles, no Ghidra."""

import unittest

from ghlab import campaign


def prof(imports=(), strings=()):
    return {"imports": set(imports), "strings": set(strings)}


class ScoreTest(unittest.TestCase):
    def test_jaccard_handles_empty_and_partial_overlap(self):
        self.assertEqual(campaign.jaccard([], []), 0.0)
        self.assertEqual(campaign.jaccard(["a"], []), 0.0)
        self.assertAlmostEqual(campaign.jaccard(["a", "b"], ["b", "c"]), 1 / 3)

    def test_imports_dominate_the_score(self):
        same_imports = campaign.pair_score(
            prof(imports=["a", "b"]), prof(imports=["a", "b"], strings=["x", "y", "z"])
        )
        same_strings = campaign.pair_score(
            prof(imports=["a", "b"], strings=["x"]), prof(imports=["c", "d"], strings=["x"])
        )
        self.assertGreater(same_imports, same_strings)


class ClusterTest(unittest.TestCase):
    def test_identical_profiles_share_a_cluster(self):
        profiles = {
            "a.exe": prof(imports=["A", "B"], strings=["s1", "s2"]),
            "b.exe": prof(imports=["A", "B"], strings=["s1", "s2"]),
            "c.exe": prof(imports=["Z"], strings=["other"]),
        }
        clusters = campaign.cluster_programs(profiles, min_score=0.5)
        sizes = [c["size"] for c in clusters]
        self.assertEqual(sizes, [2, 1])
        big = clusters[0]
        self.assertEqual(big["members"], ["a.exe", "b.exe"])
        self.assertEqual(big["max_score"], 1.0)
        self.assertIn("A", big["shared_imports"])

    def test_threshold_controls_grouping(self):
        profiles = {
            "a.exe": prof(imports=["A", "B", "C", "D"]),
            "b.exe": prof(imports=["A", "B", "X", "Y"]),
        }
        self.assertEqual(len(campaign.cluster_programs(profiles, min_score=0.5)), 2)
        merged = campaign.cluster_programs(profiles, min_score=0.2)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["size"], 2)

    def test_singletons_are_reported_too(self):
        profiles = {"only.exe": prof(imports=["A"], strings=["s"])}
        clusters = campaign.cluster_programs(profiles)
        self.assertEqual(clusters[0]["members"], ["only.exe"])
        self.assertEqual(clusters[0]["max_score"], 0.0)
        self.assertEqual(clusters[0]["shared_imports"], [])

    def test_transitive_linkage_merges_through_a_bridge(self):
        # a~b and b~c, a!~c: single linkage keeps them in one family
        # 2 shared of 4 imports = 0.30 exactly; a and c share only 1 of 5 = 0.12
        profiles = {
            "a.exe": prof(imports=["A", "B", "C"]),
            "b.exe": prof(imports=["B", "C", "D"]),
            "c.exe": prof(imports=["C", "D", "E"]),
        }
        self.assertEqual(campaign.pair_score(profiles["a.exe"], profiles["c.exe"]), 0.12)
        self.assertEqual(len(campaign.cluster_programs(profiles, min_score=0.3)), 1)

    def test_profile_flattens_function_fingerprints(self):
        prints = {
            "functions": {
                1: {"imports": {"A"}, "strings": {"s1"}},
                2: {"imports": {"B"}, "strings": {"s1", "s2"}},
            }
        }
        p = campaign.profile_from_fingerprints(prints)
        self.assertEqual(p["imports"], {"A", "B"})
        self.assertEqual(p["strings"], {"s1", "s2"})
        self.assertEqual(p["functions"], 2)

    def test_empty_program_set_is_not_an_error(self):
        self.assertEqual(campaign.cluster_programs({}), [])


if __name__ == "__main__":
    unittest.main()
