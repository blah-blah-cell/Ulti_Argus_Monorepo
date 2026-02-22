from src.argus_plugins.manager import ArgusPlugin
import logging

class DICOMInspector(ArgusPlugin):
    def name(self):
        return "DICOMInspector"

    def description(self):
        return "Deep Packet Inspection for Medical Imaging Data (DICOM) to prevent leaks."

    def on_load(self):
        self.logger = logging.getLogger("DICOM")
        # DICOM Magic Number "DICM" 
        self.magic = b"DICM"
        self.keywords = {
            b"PatientName": 10,
            b"PatientID": 10,
            b"PatientBirthDate": 8,
            b"PatientSex": 2,
            b"StudyDate": 5,
            b"InstitutionName": 7,
            b"ReferringPhysicianName": 9,
            b"Modality": 1
        }

    def on_payload(self, content: bytes):
        if self.magic in content:
            self.logger.warning("[!] DICOM MEDICAL DATA DETECTED IN STREAM!")
            
            risk_score = 0
            found_leaks = []
            
            for k, weight in self.keywords.items():
                if k in content:
                    risk_score += weight
                    found_leaks.append(k.decode('utf-8'))
            
            if risk_score > 0:
                 severity = "CRITICAL" if risk_score > 15 else "WARNING"
                 return {
                     "alert": "PHI_LEAK", 
                     "score": risk_score,
                     "details": f"Cleartext PHI found: {found_leaks}",
                     "threat_level": severity
                 }
            else:
                 return {"info": "DICOM stream detected (Anonymized/Metadata only)"}
        return None
