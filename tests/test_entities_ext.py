from src.detector.entities import EntityExtractor
from src.detector.schemas import EntityType


def test_extract_ipv4_and_ipv6():
    text = "Client connected from 192.168.1.100 and fe80:0000:0000:0000:0202:b3ff:fe1e:8329"
    ex = EntityExtractor()
    entities = ex.extract_from_text(text)
    ids = {e.entity_id for e in entities}
    assert "192.168.1.100" in ids
    assert any('fe80' in eid for eid in ids)


def test_extract_arn_boost_confidence():
    arn = "arn:aws:iam::123456789012:role/SampleRole"
    ex = EntityExtractor()
    entities = ex._extract_from_arn(arn, "userIdentity.arn")
    assert entities
    # confidence boosted but <= 0.95
    assert all(0.0 <= e.confidence <= 0.95 for e in entities)


def test_deduplication_of_entities():
    text = "role arn:aws:iam::123456789012:role/SampleRole called by arn:aws:iam::123456789012:role/SampleRole"
    ex = EntityExtractor()
    entities = ex.extract_from_text(text, confidence_threshold=0.0)
    # Should deduplicate identical finds
    ids = [(e.entity_type, e.entity_id) for e in entities]
    assert len(ids) == len(set(ids))
