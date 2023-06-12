import logging
import tempfile
import re
import random
import sys
import os
import sqlite3
import csv
from itertools import compress
import datetime
from datetime import datetime
import faulthandler
import io
import string
import textract


logger = logging.getLogger('rSMBi')


class SMBSR(object):
    def __init__(self, workername, options, db, file, share, ip, tag):
        super(SMBSR, self).__init__()
        self.options = options
        self.workername = workername
        self.db = db
        self.file = file
        self.share = share
        self.ip = ip
        self.tag = tag

    def retrieveTextSpecial(self, file_object):
        try:
            # os.rename(file_object.name, file_object.name + ".docx")
            text = textract.process(file_object.name)
            logger.debug("hello " + file_object.name)
            return text
        except Exception as e:
            os.remove(file_object.name)
            logger.error(f"[{self.workername}] | Error while parsing special file " +
                         file_object.name + " with exception: " + str(e))
            return "textractfailed"

    def get_bool(self, prompt):
        while True:
            try:
                return {"y": True, "n": False}[input(prompt).lower()]
            except KeyError:
                logger.error(
                    f"[{self.workername}] | Invalid input please enter [y/n]")

    def retrieveTimes(self, filename):
        try:
            times = []

            stats = os.stat(filename)

            ts_created = datetime.fromtimestamp(
                stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
            ts_accessed = datetime.fromtimestamp(
                stats.st_atime).strftime('%Y-%m-%d %H:%M:%S')
            ts_modified = datetime.fromtimestamp(
                stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            times.append(ts_created)
            times.append(ts_modified)
            times.append(ts_accessed)
            return times
        except Exception as e:
            logger.error(f"[{self.workername}] | Error while retrieving timestamp of file: " +
                         filename + "with exception: " + str(e))

    def passwordSMBSR(self, text, filename, to_match, counter):
        try:
            if text == "" or text is None:
                return False

            results = []
            output = False
            lbound = 0
            ubound = 0
            tosave = ""
            substartidx = 0
            words = to_match["words"]
            regex = to_match["regex"]
            for substring in words:
                results.append(substring.lower() in text.lower())
            output = any(results)
            if output:
                try:
                    m = [i for i, x in enumerate(results) if x]
                    for z in m:
                        logger.info(f"[{self.workername}] | Found interesting match in " +
                                    filename + " with " + words[z] + ", line: " + str(counter))
                        substartidx = (text.lower()).find(words[z].lower())
                        if len(text) < 50:
                            tosave = text
                        else:
                            if substartidx < 25:
                                lbound = 0
                            else:
                                lbound = substartidx - 25
                            if (len(text) - (substartidx+len(words[z]))) < 25:

                                ubound = len(text)
                            else:
                                ubound = (substartidx+len(words[z]) + 25)

                            tosave = text[lbound:ubound]

                        self.db.insertFinding(filename, self.share, self.ip, str(counter), words[z], self.retrieveTimes(
                            filename), self.options.tag, tosave.replace("\n", " "))
                        return True
                except Exception as e:
                    logger.debug(
                        f"[{self.workername}] | Error while looking for strings to match")
            if len(regex) > 0:
                for i in regex:
                    try:
                        matchedraw = re.search(i, text)
                        if matchedraw:
                            matched = (matchedraw).group(0)
                            logger.info(f"[{self.workername}] | Found interesting match in " +
                                        filename + " with regex " + i + ", line: " + str(counter))
                            substartidx = (text.lower()).find(matched.lower())

                            if len(text) < 50:
                                tosave = text
                            else:
                                if substartidx < 25:
                                    lbound = 0
                                else:
                                    lbound = substartidx - 25
                                if (len(text) - (substartidx+len(matched))) < 25:

                                    ubound = len(text)
                                else:
                                    ubound = (substartidx+len(matched) + 25)

                                tosave = text[lbound:ubound]
                            self.db.insertFinding(filename, self.share, self.ip, str(counter), words[z], self.retrieveTimes(
                                filename), self.options.tag, tosave.replace("\n", " "))
                            return True
                    except Exception as e:
                        logger.debug(
                            f"[{self.workername}] | Error while looking for regexp: "+str(i))
            return False
        except Exception as e:
            logger.debug(
                f"[{self.workername}] | Error while parsing line of file: "+str(e))

    def parse(self, filename, to_match, options):
        line_counter = 0
        hits = 0
        # file_obj = tempfile.NamedTemporaryFile()

        file_ext = (filename.split('/')[-1]).split('.')[-1] or "empty"
        if file_ext.lower() in self.options.file_extensions_black.split(','):
            logger.debug(
                f"[{self.workername}] | This extensions is blacklisted")
        else:
            if file_ext.lower() in self.options.file_interesting.split(','):
                logger.info(
                    f"[{self.workername}] | Found interesting file: " + filename)
                self.db.insertFileFinding(filename, self.share, self.ip, self.retrieveTimes(
                    filename), self.options.tag)
            if (filename.split('/')[-1]).split('.')[0].lower() in to_match["words"]:
                logger.info(
                    f"[{self.workername}] | Found interesting file named " + filename)
                self.db.insertFileFinding(filename, self.share, self.ip, self.retrieveTimes(
                    filename), self.options.tag)
            # here probably the start of the try/catch
            try:
                filesize = os.path.getsize(filename)
            except Exception as e:
                logger.error(
                    f"[{self.workername}] | Error while retrieving the file size, skipping")
                return

            if filesize > self.options.max_size:
                logger.debug(f"[{self.workername}] | Skipping file " +
                             filename + ", it is too big and you said i can't handle it")

            elif len(to_match["words"]) > 0 or len(to_match["regex"]) > 0:
                try:
                    file_obj = open(filename, "r")
                except Exception as e:
                    logger.error(
                        f"[{self.workername}] | Error while opening handle to file")
                    return
                # here the extension check for office files
                if file_ext.lower() in ['docx', 'doc', 'docx', 'eml', 'epub', 'gif', 'jpg', 'mp3', 'msg', 'odt', 'ogg', 'pdf', 'png', 'pptx', 'ps', 'rtf', 'tiff', 'tif', 'wav', 'xlsx', 'xls']:

                    lines = (self.retrieveTextSpecial(file_obj))
                    file_obj.close()
                    if lines != "textractfailed":
                        lines = lines.split(b' ')
                        try:
                            os.remove(filename)
                        except Exception as e:
                            logger.error(
                                f"[{self.workername}] | Error deleting the temp file: " + filename)

                else:
                    file_obj.seek(0)
                    try:
                        lines = file_obj.readlines()
                    except Exception as e:
                        logger.error(f"[{self.workername}] | Encountered exception while reading file: " +
                                     filename + " with extension " + file_ext + " | Exception: " + str(e))
                        return
                    # need to work on the lines here bcs the strip with bytes does not work apparently

                if len(lines) > 0 and lines != "textractfailed":
                    for line in lines:
                        line_counter += 1
                        try:

                            if self.passwordSMBSR(line.rstrip(), filename, to_match, line_counter):
                                hits += 1
                                if hits >= options.hits:
                                    logger.debug(
                                        f"[{self.workername}] | Reached max hits for " + filename)
                                    break
                        except Exception as e:
                            logger.error(f"[{self.workername}] | Encountered exception while analyzing file line: " +
                                         filename + " with extension " + file_ext + " | Exception: " + str(e))
                            break
        file_obj.close()
