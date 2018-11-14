

object TraceAnalysis {
  import org.apache.spark.{SparkConf, SparkContext}
  import org.apache.spark.sql.{SaveMode, SparkSession}
  import org.apache.log4j.{Level, Logger}
  import java.io.File

  def main(args: Array[String]): Unit = {

    Logger.getLogger("org").setLevel(Level.OFF)

    // initialize spark session

    val spark = SparkSession
      .builder()
      .appName("Word Count")
      .master("local")
      .config("spark.some.config.option", "some-value")
      .getOrCreate()


    import spark.implicits._

    val tdf = spark.read.option("multiline", "true").json("../test1.json")
    //tdf.printSchema()

    //tdf.createOrReplaceTempView("tdf")
    //tdf.show(1,false).toString
    val tdf_2 = tdf.select(tdf.col("_source.layers.tcp"))
    tdf_2.printSchema()
    print(tdf_2.where($"tcp" isNotNull).count.toInt)

    println("HelloWorld!")
  }
}