import sqlite3
import csv
import threading
import logging
import sys
import datetime
from datetime import datetime

logger = logging.getLogger('rSMBi')


class Database:
    def __init__(self, db_file):
        self.db_file = db_file

    def connect_database(self):
        self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.lock = threading.Lock()

    def create_database(self):
        self.connect_database()
        try:
            rsmbi_match_table = """ CREATE TABLE IF NOT EXISTS rsmbi (
                                            id integer PRIMARY KEY AUTOINCREMENT,
                                            file text NOT NULL,
                                            share text NOT NULL,
                                            ip text NOT NULL,
                                            tsFirstFound text NOT NULL,
                                            tsLastFound text NOT NULL,
                                            runTag text NOT NULL,
                                            winClickable text NOT NULL
                                        ); """

            if self.cursor is not None:
                self.create_table(rsmbi_match_table)

        except Exception as e:
            logger.error(
                "Encountered error while creating the database: " + str(e))
            sys.exit(1)

    def exportToCSV(self, tag):
        cursor = self.cursor
        exportQuery = "SELECT * from rsmbi WHERE runTag = '{tag}\'".format(
            tag=tag)

        sr = cursor.execute(exportQuery)
        with open('rsmbi_results.csv', 'w') as f:
            writer = csv.writer(f)
            writer.writerows(sr)

    def commit(self):
        self.conn.commit()

    def create_table(self, create_table_sql):

        try:
            self.cursor.execute(create_table_sql)
        except Exception as e:
            logger.error(e)

    def insertFinding(self, filename, share, ip, tag):
        now = datetime.now()
        date = now.strftime("%d-%m-%Y")
        # remove the local path tmp path

        filename = '/'.join(filename.split('/')[3:])
        clickable = ("\\\\" + ip + "\\" + share +
                     "\\" + filename).replace('/', '\\')

        try:
            self.lock.acquire(True)
            cursor = self.cursor

            cursor.execute('SELECT id,file FROM rsmbi WHERE ip = ? AND share = ? AND file = ?', (
                ip, share, filename))

            results = cursor.fetchall()

            if len(results) == 0:

                insertFindingQuery = "INSERT INTO rsmbi (file, share, ip, tsFirstFound, tsLastFound, runTag, winClickable) VALUES (?,?,?,?,?,?,?)"
                cursor.execute(insertFindingQuery,
                               (filename, share, ip, date, date, tag, clickable.replace("/", "\\")))
                self.commit()
            else:

                updateQuery = 'UPDATE rsmbi SET tsLastFound = ? WHERE ip = ? AND share = ? AND file= ?'
                cursor.execute(updateQuery, (date, ip, share,
                               filename))
                self.commit()

                updateQuery = 'UPDATE rsmbi SET runTag = ? WHERE ip = ? AND share = ? AND file= ?'
                cursor.execute(updateQuery, (tag, ip, share,
                               filename))

        except Exception as e:
            logger.error("Error while updating database: " + str(e))
            self.lock.release()
        finally:
            self.lock.release()


class DatabaseSMBSR:
    def __init__(self, db_file):
        self.db_file = db_file

    def connect_database(self):
        self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.lock = threading.Lock()

    def create_database(self):
        self.connect_database()
        try:
            smb_match_table = """ CREATE TABLE IF NOT EXISTS smbsr (
                                            id integer PRIMARY KEY AUTOINCREMENT,
                                            file text NOT NULL,
                                            share text NOT NULL,
                                            ip text NOT NULL,
                                            position text NOT NULL,
                                            matchedWith text NOT NULL,
                                            tsCreated text NOT NULL,
                                            tsModified text NOT NULL, 
                                            tsAccessed text NOT NULL,
                                            tsFirstFound text NOT NULL,
                                            tsLastFound text NOT NULL,
                                            runTag text NOT NULL,
                                            extract text NOT NULL,
                                            winClickable text NOT NULL
                                        ); """
            smb_files_table = """ CREATE TABLE IF NOT EXISTS smbfile (
                                id integer PRIMARY KEY AUTOINCREMENT,
                                file text NOT NULL,
                                share text NOT NULL,
                                ip text NOT NULL,
                                tsCreated text NOT NULL,
                                tsModified text NOT NULL,
                                tsAccessed text NOT NULL,
                                tsFirstFound text NOT NULL,
                                tsLastFound text NOT NULL,
                                runTag text NOT NULL,
                                winClickable text NOT NULL
                            ); """

            if self.cursor is not None:
                self.create_table(smb_match_table)
                self.create_table(smb_files_table)

        except Exception as e:
            logger.error(
                "Encountered error while creating the database: " + str(e))
            sys.exit(1)

    def exportToCSV(self, tag):
        cursor = self.cursor
        exportQuery = "SELECT * from smbsr WHERE runTag = '{tag}\'".format(
            tag=tag)
        exportQueryFile = "SELECT * from smbfile WHERE runTag = '{tag}\'".format(
            tag=tag)

        sr = cursor.execute(exportQuery)
        with open('smbsr_results.csv', 'w') as f:
            writer = csv.writer(f)
            writer.writerows(sr)
        sf = cursor.execute(exportQueryFile)
        with open('smbsrfile_results.csv', 'w') as g:
            writer = csv.writer(g)
            writer.writerows(sf)

    def commit(self):
        self.conn.commit()

    def create_table(self, create_table_sql):

        try:
            self.cursor.execute(create_table_sql)
        except Exception as e:
            logger.error(e)

    def insertFinding(self, filename, share, ip, line, matchedwith, times, tag, text):

        filename = '/'.join(filename.split('/')[3:])
        clickable = ("\\\\" + ip + "\\" + share +
                     "\\" + filename).replace('/', '\\')
        now = datetime.now()
        date = now.strftime("%d-%m-%Y")
        try:
            self.lock.acquire(True)
            cursor = self.cursor
            results = cursor.execute('SELECT id, extract FROM smbsr WHERE ip = ? AND share = ? AND file = ? AND matchedWith = ? AND position = ?', (
                ip, share, filename, matchedwith, line)).fetchall()

            if len(results) == 0:
                insertFindingQuery = "INSERT INTO smbsr (file, share, ip, position, matchedWith, tsCreated, tsModified, tsAccessed, tsFirstFound, tsLastFound, runTag, extract, winClickable) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
                cursor.execute(insertFindingQuery, (filename, share, ip, line,
                               matchedwith, times[0], times[1], times[2], date, date, tag, text, clickable))
                self.commit()
            else:
                textOld = ((results[0])[1])
                updateQuery = 'UPDATE smbsr SET tsLastFound = ? WHERE ip = ? AND share = ? AND file= ? AND matchedWith = ? AND position = ? '
                cursor.execute(updateQuery, (date, ip, share,
                               filename, matchedwith, line))
                self.commit()
                if textOld != text:
                    updateQuery = 'UPDATE smbsr SET extract = ? WHERE ip = ? AND share = ? AND file = ? AND matchedWith = ? AND position = ?'
                    cursor.execute(updateQuery, (text, ip, share,
                                   filename, matchedwith, line))
                    self.commit()
                    updateQuery = 'UPDATE smbsr SET runTag = ? WHERE ip = ? AND share = ? AND file = ? AND matchedWith = ? AND position = ? AND extract = ?'
                    cursor.execute(updateQuery, (tag, text, ip,
                                   share, filename, matchedwith, line))
                    self.commit()
        except Exception as e:
            logger.error(
                "Error while updating database for secret match: " + str(e))
            self.lock.release()
        finally:
            self.lock.release()

    def insertFileFinding(self, filename, share, ip, times, tag):
        now = datetime.now()
        date = now.strftime("%d-%m-%Y")
        clickable = ("\\\\" + ip + "\\" + share +
                     "\\" + filename).replace('/', '\\')
        try:
            self.lock.acquire(True)
            cursor = self.cursor
            checkQuery = 'SELECT id FROM smbfile WHERE ip = ? AND share = ? AND file = ?'
            results = cursor.execute(
                checkQuery, (ip, share, filename)).fetchall()

            if len(results) == 0:
                insertFindingQuery = "INSERT INTO smbfile (file, share, ip, tsCreated, tsModified, tsAccessed, tsFirstFound, tsLastFound, runTag, winClickable) VALUES (?,?,?,?,?,?,?,?,?,?)"
                cursor.execute(insertFindingQuery, (filename, share,
                               ip, times[0], times[1], times[2], date, date, tag, clickable))
                self.commit()
            else:

                updateQuery = 'UPDATE smbfile SET tsLastFound = ? WHERE ip= ? AND share = ? AND file = ?'
                cursor.execute(updateQuery, (date, ip, share, filename))
                self.commit()
                updateQuery = 'UPDATE smbfile SET runTag = ? WHERE ip= ? AND share = ? AND file = ?'
                cursor.execute(updateQuery, (tag, ip, share, filename))
                self.commit()
        except Exception as e:
            logger.error(
                "Error while updating database for file finding: " + str(e))
            self.lock.release()
        finally:
            self.lock.release()
