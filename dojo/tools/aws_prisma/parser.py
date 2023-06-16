import io
import csv
import textwrap
import uuid
from datetime import date
from dateutil.parser import parse
from dojo.models import Finding


class AWSPrismaParser(object):
    SCAN_TYPE = ["AWS Prisma CSV"]

    def get_scan_types(self):
        return AWSPrismaParser.SCAN_TYPE

    def get_label_for_scan_types(self, scan_type):
        return AWSPrismaParser.SCAN_TYPE[0]

    def get_description_for_scan_types(self, scan_type):
        return "AWS Prisma CSV format."

    def get_findings(self, file, test):
        if file.name.lower().endswith('.csv'):
            return self.process_csv(file, test)
        else:
            raise ValueError('Unknown file format')

    def get_severity(self, sev):
        if sev == 'informational':
            return 'Info'
        return sev.capitalize()

    def process_csv(self, file, test):
        content = file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        csv_reader = csv.DictReader(io.StringIO(content))

        findings = []

        for row in csv_reader:

            status = row.get('Alert Status', '')
            if status != 'open':
                continue

            unique_id_from_tool = row.get('Alert ID', uuid.uuid4())
            component_name = row.get('Resource ID', '')
            title = f"{row.get('Policy Name','')} - {component_name}"
            account_id = row.get('Cloud Account Id', '')
            account_name = row.get('Cloud Account Name', '')
            account = f"{account_name} - {account_id}"
            region = row.get('Region', '')
            severity = self.get_severity(row.get('Policy Severity', 'Info'))
            dateFile = row.get('Alert Time', date.today().strftime('%b %d, %Y'))
            dateFind = parse(dateFile[0:12])
            mitigation = row.get('Recommendation')
            compliance = row.get('Policy Labels', '')

            description = "**Issue:** " + str(title) + \
                "\n**Description:** " + str(row.get('Description', '')) + \
                "\n**AWS Account:** " + str(account) + " | **Region:** " + str(region) + \
                "\n**Compliance:** " + str(compliance)

            find = Finding(
                title=textwrap.shorten(title, 150),
                cwe=1032,
                test=test,
                description=description,
                component_name=component_name,
                unique_id_from_tool=unique_id_from_tool,
                severity=severity,
                date=dateFind,
                static_finding=True,
                dynamic_finding=False,
                nb_occurences=1,
                mitigation=mitigation,
            )
            findings.append(find)
        return findings
